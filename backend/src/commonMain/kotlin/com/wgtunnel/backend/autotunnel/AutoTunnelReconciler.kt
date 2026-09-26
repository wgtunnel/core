package com.wgtunnel.backend.autotunnel

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.state.BackendStatus
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.conflate
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

interface TunnelActions {
    /** Bounded, and reports failure by logging. Success is judged by the running set after start. */
    suspend fun start(id: Long)

    suspend fun stop(id: Long)
}

/**
 * How the platform changes the running tunnels.
 */
interface AutoTunnelHost {
    /**
     * Runs [block] holding the same lock every user start/stop holds. Auto tunnel decides and acts
     * inside it, so nothing can change in between and any user action that ran first has already
     * flagged its override.
     */
    suspend fun <T> exclusively(block: suspend (TunnelActions) -> T): T
}

/**
 * Drives the running tunnels toward what [AutoTunnelEngine] wants, from live state.
 *
 * A single worker, triggers are conflated and never cancel work in flight. Each pass takes the
 * host's lock, reads the latest inputs and the live running set, acts, and repeats until the
 * engine has nothing left to do. Rapid network changes collapse into one pass against the newest
 * state, and the end state is always the engine's decision for the latest inputs.
 */
class AutoTunnelReconciler(
    private val scope: CoroutineScope,
    private val status: StateFlow<BackendStatus>,
    private val host: AutoTunnelHost,
    private val engine: AutoTunnelEngine = AutoTunnelEngine(),
    private val startupSettle: Duration = Duration.ZERO,
    private val noInternetGrace: Duration = 10.seconds,
    private val retryDelay: Duration = 400.milliseconds,
) {
    private val log = Logger.withTag("AutoTunnelReconciler")

    private enum class Pass {
        Settled,
        Progressed,
        Stalled,
    }

    private var job: Job? = null
    private var noInternetJob: Job? = null

    @Volatile private var latest: AutoTunnelSnapshot? = null
    @Volatile private var hasUserOverride = false
    private var lastNetworkKey: String? = null
    private var settled = false

    // Inputs we stopped retrying for. Our own failed starts pulse the running set, which would
    // otherwise re-trigger forever, so we wait for the inputs to change.
    private var gaveUpOn: AutoTunnelSnapshot? = null

    /**
     * [inputs] is the network, policy and tunnels.
     */
    fun start(inputs: Flow<AutoTunnelSnapshot>) {
        stop()
        latest = null
        hasUserOverride = false
        lastNetworkKey = null
        settled = false
        gaveUpOn = null
        job =
            scope.launch {
                combine(
                        inputs.onEach {
                            latest = it
                            updateFingerprint(it)
                        },
                        status.map { it.activeTunnels.keys }.distinctUntilChanged(),
                    ) { _, _ ->
                    }
                    .conflate()
                    .collect {
                        if (!settled) {
                            delay(startupSettle)
                            settled = true
                        }
                        converge()
                    }
            }
    }

    fun stop() {
        job?.cancel()
        job = null
        cancelNoInternetStop()
    }

    fun notifyUserOverride() {
        if (!hasUserOverride) {
            log.d { "User override on current network, pausing auto decisions" }
        }
        hasUserOverride = true
    }

    // Each pass takes the lock on its own, so the back-off between passes never holds it
    private suspend fun converge() {
        var stalled = 0
        repeat(MAX_PASSES) {
            when (host.exclusively { actions -> pass(actions) }) {
                Pass.Settled -> return
                Pass.Progressed -> stalled = 0
                Pass.Stalled -> {
                    if (++stalled >= MAX_STALLED) {
                        log.w { "No progress after $stalled attempts, waiting for inputs to change" }
                        gaveUpOn = latest
                        return
                    }
                    delay(retryDelay)
                }
            }
        }
        log.w { "Did not settle after $MAX_PASSES passes" }
    }

    private suspend fun pass(actions: TunnelActions): Pass {
        val snapshot = latest ?: return Pass.Settled
        if (hasUserOverride) return Pass.Settled
        if (gaveUpOn != null) {
            if (gaveUpOn == snapshot) return Pass.Settled
            gaveUpOn = null
        }

        val before = activeTunnelIds()
        return when (val decision = engine.evaluate(snapshot.copy(activeTunnelIds = before))) {
            AutoTunnelDecision.DoNothing -> Pass.Settled
            AutoTunnelDecision.StopAllDueToNoInternet -> {
                scheduleNoInternetStop()
                Pass.Settled
            }
            is AutoTunnelDecision.Sync -> {
                cancelNoInternetStop()
                log.i { "Reconciling active=$before start=${decision.start} stop=${decision.stop}" }
                apply(decision, actions)
                if (activeTunnelIds() != before) Pass.Progressed else Pass.Stalled
            }
        }
    }

    // Cancelling a start halfway leaves a half-built tunnel, so the actions of a pass always run to
    // completion. If the reconciler is stopped meanwhile, that takes effect once they finish.
    private suspend fun apply(decision: AutoTunnelDecision.Sync, actions: TunnelActions) =
        withContext(NonCancellable) {
            decision.stop.forEach { id ->
                runCatching { actions.stop(id) }
                    .onFailure { log.e(it) { "Failed to stop tunnel $id" } }
            }
            decision.start.forEach { id ->
                runCatching { actions.start(id) }
                    .onFailure { log.e(it) { "Failed to start tunnel $id" } }
            }
        }

    private fun activeTunnelIds(): Set<Long> =
        status.value.activeTunnels.keys.map { it.toLong() }.toSet()

    // Tracked as inputs arrive, not when a pass runs, so a network change clears the override when
    // it happens and an override set after it can't be cleared by a pass that was queued behind it
    private fun updateFingerprint(snapshot: AutoTunnelSnapshot) {
        val bssidAware =
            snapshot.policy.trustedNetworkBssids.isNotEmpty() ||
                snapshot.tunnels.any { it.tunnelBssids.isNotEmpty() }
        val key = snapshot.network.fingerprint(bssidAware)
        if (lastNetworkKey != key) {
            if (hasUserOverride) log.d { "Network changed, clearing user override" }
            hasUserOverride = false
            lastNetworkKey = key
        }
    }

    // Grace period so flaky networks and transitions don't drop the tunnel
    private fun scheduleNoInternetStop() {
        if (noInternetJob?.isActive == true) return
        noInternetJob =
            scope.launch {
                delay(noInternetGrace)
                host.exclusively { actions ->
                    val snapshot = latest ?: return@exclusively
                    if (
                        hasUserOverride ||
                            snapshot.network.hasUsableNetwork ||
                            !snapshot.policy.isStopOnNoInternetEnabled
                    ) {
                        log.d { "No internet grace expired, nothing to stop" }
                        return@exclusively
                    }
                    val running = activeTunnelIds()
                    if (running.isEmpty()) return@exclusively
                    log.w { "No internet grace expired, stopping tunnels $running" }
                    withContext(NonCancellable) {
                        running.forEach { id ->
                            runCatching { actions.stop(id) }
                                .onFailure { log.e(it) { "Failed to stop tunnel $id" } }
                        }
                    }
                }
            }
    }

    private fun cancelNoInternetStop() {
        noInternetJob?.cancel()
        noInternetJob = null
    }

    private companion object {
        const val MAX_PASSES = 8
        const val MAX_STALLED = 3
    }
}
