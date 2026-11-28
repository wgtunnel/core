package com.wgtunnel.backend.features

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.Tunnel
import com.wgtunnel.backend.enums.FamilyOverride
import com.wgtunnel.backend.enums.Ipv6Support
import com.wgtunnel.backend.event.TunnelEvent
import com.wgtunnel.backend.model.BackendMode
import com.wgtunnel.backend.model.dns.BootstrapResolution
import com.wgtunnel.backend.model.dns.DnsBootstrapResult
import com.wgtunnel.backend.state.ActiveTunnel
import com.wgtunnel.backend.util.PublicKey
import com.wgtunnel.backend.util.buildResolvedPeers
import com.wgtunnel.backend.util.ddnsRecoveryFamily
import com.wgtunnel.backend.util.findEndpointMismatches
import com.wgtunnel.backend.util.hasIpv4Peers
import com.wgtunnel.backend.util.hasIpv6Peers
import com.wgtunnel.backend.util.withEndpointsFrom
import com.wgtunnel.parser.ActiveConfig
import com.wgtunnel.parser.PeerSection
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeMark
import kotlin.time.TimeSource
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

internal class TunnelRecovery(
    private val tunnelId: Int,
    private val mode: BackendMode,
    private val stabilizeWindow: Duration,
    private val host: Host,
) {

    private val log = Logger.withTag("TunnelRecovery")

    @OptIn(ExperimentalAtomicApi::class)
    private var lastIpv4FallbackNetworkKey: AtomicReference<String?> = AtomicReference(null)

    @OptIn(ExperimentalAtomicApi::class)
    private var lastIpv6RecoveryNetworkKey: AtomicReference<String?> = AtomicReference(null)

    private val dynamicPeerKeys: Set<PublicKey> =
        mode.config.peers
            .filter { !it.isStaticallyConfigured && it.endpoint != null }
            .map { it.publicKey }
            .toSet()

    interface Host {
        fun observe(): Flow<Snapshot>

        suspend fun getActiveConfig(): ActiveConfig?

        suspend fun resolveFresh(): BootstrapResolution?

        suspend fun updatePeers(peers: List<PeerSection>)

        suspend fun bounce(withFreshResolution: Boolean): Boolean

        fun updateActiveTunnel(transform: (ActiveTunnel) -> ActiveTunnel)

        suspend fun emit(event: TunnelEvent)
    }

    data class Snapshot(
        val shouldArmFailureRecovery: Boolean,
        // True while not Healthy and network usable. Keeps an armed episode alive across bounce
        // Down/Starting.
        val shouldKeepFailureRecoveryEpisode: Boolean,
        val transportHealthy: Boolean,
        val bootstrapPending: Boolean,
        val lastResolvedPeers: Map<PublicKey, DnsBootstrapResult>?,
        val networkIpv6: Ipv6Support,
        val activeNetworkKey: String?,
        // Whether the platform verified internet on the active network
        val networkValidated: Boolean = true,
        val deviceAwake: Boolean,
        // Goes up on every wake signal, screen on, unlock, leaving Doze, resume from sleep
        val wakeEpoch: Long = 0L,
        val recovery: Tunnel.Feature.Recovery = IDLE_RECOVERY,
    )

    fun start(scope: CoroutineScope): Job = scope.launch {
        launch { runFailureRecovery() }
        launch { runIpv6EndpointRecoveryJob() }
    }

    private enum class LoopStep {
        BREAK_EPISODE,
        CONTINUE_EPISODE,
        PROCEED,
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun CoroutineScope.runFailureRecovery() {
        launch {
            // Wakes and network changes are counted here, before a snapshot is published, so the
            // loop below can never see one without its signal
            val signals = AtomicInt(0)
            val lastSignal = AtomicReference<TimeMark?>(null)
            var lastWake: Long? = null
            var lastKey: String? = null
            var lastValidated = true

            val snapshots =
                host
                    .observe()
                    .onEach { snap ->
                        val previousWake = lastWake
                        val woke = previousWake != null && snap.wakeEpoch != previousWake
                        val moved =
                            previousWake != null &&
                                snap.activeNetworkKey != null &&
                                snap.activeNetworkKey != lastKey
                        // Internet back on the same network, like cellular coming back into
                        // coverage without the data connection having dropped
                        val regained =
                            previousWake != null &&
                                !moved &&
                                snap.activeNetworkKey != null &&
                                !lastValidated &&
                                snap.networkValidated
                        lastWake = snap.wakeEpoch
                        snap.activeNetworkKey?.let { lastKey = it }
                        lastValidated = snap.networkValidated
                        if (woke || moved || regained) {
                            lastSignal.store(TimeSource.Monotonic.markNow())
                            signals.fetchAndAdd(1)
                        }
                    }
                    .stateIn(
                        scope = this,
                        started = SharingStarted.Eagerly,
                        initialValue =
                            Snapshot(
                                shouldArmFailureRecovery = false,
                                shouldKeepFailureRecoveryEpisode = false,
                                transportHealthy = false,
                                bootstrapPending = false,
                                lastResolvedPeers = null,
                                networkIpv6 = Ipv6Support.Unknown,
                                activeNetworkKey = null,
                                deviceAwake = false,
                            ),
                    )

            launch { snapshots.collect { snap -> log.d { "Running with state $snap" } } }
            launch {
                snapshots
                    .map { it.recovery }
                    .distinctUntilChanged()
                    .collect { rec ->
                        log.i {
                            "Recovery features for tunnel $tunnelId: " +
                                "seamless=${rec.seamlessRecovery} " +
                                "ddns=${rec.dynamicDnsRecovery} " +
                                "ipv4Fallback=${rec.ipv4Fallback} " +
                                "ipv6=${rec.ipv6Recovery} " +
                                "ipv6Fallback=${rec.ipv6Fallback} " +
                                "bounceDelay=${rec.bounceDelaySeconds}s"
                        }
                    }
            }

            var seamlessRecoveryAttempted = 0
            var exhausted = false
            // When the last bounce ran, for the cooldown on the quick settle
            var lastBounce: TimeMark? = null
            // The first bounce after a wake or network change waits only a short settle
            var fastSettle = false
            // One IPv6 fallback per episode
            var ipv6FallbackTried = false
            var seenSignals = signals.load()

            fun changedSince(): Boolean = signals.load() != seenSignals

            // Only peers on IPv4 are candidates. A peer already on IPv6 leaves the episode
            // unlatched, so a later fallback to a dead A record gets an IPv6 try.
            suspend fun willTryIpv6(snap: Snapshot): Boolean =
                snap.recovery.ipv6Fallback &&
                    !ipv6FallbackTried &&
                    snap.networkIpv6 == Ipv6Support.Available &&
                    snap.activeNetworkKey != null &&
                    // IPv6 already failed here and fell back to IPv4
                    snap.activeNetworkKey != lastIpv4FallbackNetworkKey.load() &&
                    host.getActiveConfig()?.hasIpv4Peers() == true

            // Only when a hostname peer is on IPv6, otherwise there is nothing to fall back and
            // the stabilize windows would only delay the bounce. A static IPv6 peer has no A
            // record, so it never makes the fallback switch and set its network key.
            suspend fun willTryIpv4(snap: Snapshot): Boolean =
                snap.recovery.ipv4Fallback &&
                    snap.activeNetworkKey != null &&
                    snap.activeNetworkKey != lastIpv4FallbackNetworkKey.load() &&
                    host.getActiveConfig()?.hasIpv6Peers(dynamicPeerKeys) == true

            // A wake, unlock or new network makes earlier attempts stale, so the budget refills.
            fun refreshBudget() {
                val current = signals.load()
                if (current == seenSignals) return
                seenSignals = current
                if (seamlessRecoveryAttempted != 0 || exhausted) {
                    log.d {
                        "Recovery: wake or network change, resetting bounce attempts for tunnel $tunnelId (was $seamlessRecoveryAttempted)"
                    }
                }
                seamlessRecoveryAttempted = 0
                exhausted = false
                ipv6FallbackTried = false
                // Only a signal from the last minute earns the short settle
                fastSettle =
                    lastSignal.load()?.let { it.elapsedNow() < FRESH_SIGNAL_WINDOW } == true
            }

            // Bootstrap in flight so wait until it finishes, keeping the session active.
            suspend fun awaitBootstrap(): LoopStep {
                if (!snapshots.value.bootstrapPending) return LoopStep.PROCEED
                log.d { "Recovery: waiting for bootstrap to finish for tunnel $tunnelId" }
                snapshots.first { !it.bootstrapPending || !it.shouldKeepFailureRecoveryEpisode }
                refreshBudget()
                if (!snapshots.value.shouldKeepFailureRecoveryEpisode) return LoopStep.BREAK_EPISODE
                // Bootstrap finished while still unhealthy, fall through to a fresh stabilize
                // window before we act
                return LoopStep.PROCEED
            }

            // DDNS re-resolution, a light IPv4 fallback and a light IPv6 fallback, each behind its
            // own stabilize window. IPv6 goes last so IPv4 has had its fresh DNS attempt first.
            suspend fun attemptDdnsAndIpv4Fallback(): LoopStep {
                if (
                    !(snapshots.value.recovery.dynamicDnsRecovery ||
                        willTryIpv4(snapshots.value) ||
                        willTryIpv6(snapshots.value))
                ) {
                    return LoopStep.PROCEED
                }

                delay(stabilizeWindow)
                refreshBudget()
                if (!snapshots.value.shouldKeepFailureRecoveryEpisode) return LoopStep.BREAK_EPISODE
                if (snapshots.value.bootstrapPending) return LoopStep.CONTINUE_EPISODE

                if (snapshots.value.recovery.dynamicDnsRecovery) {
                    tryDynamicDnsRecovery(snapshots.value)
                    delay(stabilizeWindow)
                    refreshBudget()
                    if (!snapshots.value.shouldKeepFailureRecoveryEpisode) {
                        return LoopStep.BREAK_EPISODE
                    }
                    if (snapshots.value.bootstrapPending) return LoopStep.CONTINUE_EPISODE
                }

                val snap = snapshots.value
                if (willTryIpv4(snap)) {
                    tryLightIpv4Fallback(snap)
                    delay(stabilizeWindow)
                    refreshBudget()
                    if (!snapshots.value.shouldKeepFailureRecoveryEpisode) {
                        return LoopStep.BREAK_EPISODE
                    }
                    if (snapshots.value.bootstrapPending) return LoopStep.CONTINUE_EPISODE
                }

                if (willTryIpv6(snapshots.value)) {
                    when (val result = tryLightIpv6Fallback(snapshots.value)) {
                        Ipv6FallbackResult.NotChecked -> Unit
                        Ipv6FallbackResult.NoIpv6Host -> ipv6FallbackTried = true
                        is Ipv6FallbackResult.Switched -> {
                            ipv6FallbackTried = true
                            // A completed handshake ends the episode, so this returns early
                            withTimeoutOrNull(stabilizeWindow) {
                                snapshots.first { !it.shouldKeepFailureRecoveryEpisode }
                            }
                            if (!snapshots.value.transportHealthy) {
                                log.i {
                                    "Ipv6 Fallback: no handshake over IPv6, restoring previous " +
                                        "endpoints for tunnel $tunnelId"
                                }
                                host.updatePeers(result.previousPeers)
                            }
                            refreshBudget()
                            if (!snapshots.value.shouldKeepFailureRecoveryEpisode) {
                                return LoopStep.BREAK_EPISODE
                            }
                            if (snapshots.value.bootstrapPending) return LoopStep.CONTINUE_EPISODE
                        }
                    }
                }
                return LoopStep.PROCEED
            }

            // Holds until the device wakes (a bounce while asleep has no network to come up on
            // and would spend an attempt for nothing), waits out the bounce window, then
            // performs the bounce if nothing changed in the meantime.
            suspend fun waitForWindowAndBounce(): LoopStep {
                val beforeBounce = snapshots.value
                refreshBudget()
                if (!beforeBounce.recovery.seamlessRecovery || beforeBounce.bootstrapPending) {
                    // Seamless disabled or bootstrap pending
                    delay(stabilizeWindow)
                    return LoopStep.CONTINUE_EPISODE
                }

                // A bounce while asleep has no network to come up on and would spend an
                // attempt, so we hold until the device wakes or the episode ends.
                if (!beforeBounce.deviceAwake) {
                    log.d { "Recovery: device asleep, holding bounce for tunnel $tunnelId" }
                    snapshots.first { it.deviceAwake || !it.shouldKeepFailureRecoveryEpisode }
                    refreshBudget()
                    return LoopStep.CONTINUE_EPISODE
                }

                if (seamlessRecoveryAttempted >= MAX_SEAMLESS_RECOVERY_RETRIES) {
                    // Out of quick attempts. A wake, unlock, network change or internet coming
                    // back retries right away. Otherwise retry slowly, as the network can recover
                    // without any of those, like cellular coming back into coverage.
                    if (!exhausted) {
                        exhausted = true
                        log.i {
                            "Recovery: used $MAX_SEAMLESS_RECOVERY_RETRIES bounce attempts for tunnel $tunnelId, retrying every ${EXHAUSTED_RETRY_INTERVAL.inWholeMinutes} min or on a wake or network change"
                        }
                    }
                    val signalled =
                        withTimeoutOrNull(EXHAUSTED_RETRY_INTERVAL) {
                            snapshots.first {
                                !it.shouldKeepFailureRecoveryEpisode || changedSince()
                            }
                        }
                    if (signalled != null) return LoopStep.CONTINUE_EPISODE

                    val ready = snapshots.value
                    if (!ready.shouldKeepFailureRecoveryEpisode) return LoopStep.BREAK_EPISODE
                    if (
                        ready.bootstrapPending ||
                            !ready.recovery.seamlessRecovery ||
                            !ready.deviceAwake
                    ) {
                        return LoopStep.CONTINUE_EPISODE
                    }
                    log.i { "Recovery: tunnel $tunnelId still failing, retrying" }
                    if (tryFullTunnelBounce(ready.recovery.dynamicDnsRecovery)) {
                        lastBounce = TimeSource.Monotonic.markNow()
                    }
                    return LoopStep.PROCEED
                }

                val configured = beforeBounce.recovery.bounceDelaySeconds.seconds
                // The quick settle is for the first bounce after a wake or network change
                val cooledDown = lastBounce?.elapsedNow()?.let { it > FAST_BOUNCE_COOLDOWN } ?: true
                val wait =
                    if (fastSettle && cooledDown) minOf(WAKE_SETTLE, configured) else configured
                fastSettle = false

                // A wake or network change during the wait restarts it, so a network that is
                // still changing isn't bounced until it settles. The episode ending ends it.
                val interrupted =
                    withTimeoutOrNull(wait) {
                        snapshots.first { !it.shouldKeepFailureRecoveryEpisode || changedSince() }
                    }
                val ready = snapshots.value
                if (!ready.shouldKeepFailureRecoveryEpisode) return LoopStep.BREAK_EPISODE
                if (interrupted != null) {
                    refreshBudget()
                    return LoopStep.CONTINUE_EPISODE
                }
                if (ready.bootstrapPending) return LoopStep.CONTINUE_EPISODE
                if (!ready.recovery.seamlessRecovery) return LoopStep.CONTINUE_EPISODE
                // Fell asleep during the wait
                if (!ready.deviceAwake) return LoopStep.CONTINUE_EPISODE

                val bounced = tryFullTunnelBounce(ready.recovery.dynamicDnsRecovery)
                if (bounced) {
                    lastBounce = TimeSource.Monotonic.markNow()
                    if (seamlessRecoveryAttempted < MAX_SEAMLESS_RECOVERY_RETRIES) {
                        seamlessRecoveryAttempted++
                    }
                    log.i {
                        "Tunnel bounce attempt $seamlessRecoveryAttempted of $MAX_SEAMLESS_RECOVERY_RETRIES"
                    }
                } else {
                    // Not a real attempt, don't spend the budget on it
                    log.w { "Recovery: bounce did not run for tunnel $tunnelId" }
                    delay(stabilizeWindow)
                }
                return LoopStep.PROCEED
            }

            while (isActive) {
                // Arm only on HandshakeFailure, not Starting/unknown
                snapshots.first { it.shouldArmFailureRecovery }
                log.i { "Recovery episode started for tunnel $tunnelId" }
                refreshBudget()

                // Stay until Healthy (or network unusable), including bounce Down/Starting
                episode@ while (isActive && snapshots.value.shouldKeepFailureRecoveryEpisode) {
                    refreshBudget()

                    when (awaitBootstrap()) {
                        LoopStep.BREAK_EPISODE -> break@episode
                        LoopStep.CONTINUE_EPISODE -> continue@episode
                        LoopStep.PROCEED -> Unit
                    }

                    when (attemptDdnsAndIpv4Fallback()) {
                        LoopStep.BREAK_EPISODE -> break@episode
                        LoopStep.CONTINUE_EPISODE -> continue@episode
                        LoopStep.PROCEED -> Unit
                    }

                    when (waitForWindowAndBounce()) {
                        LoopStep.BREAK_EPISODE -> break@episode
                        LoopStep.CONTINUE_EPISODE -> continue@episode
                        LoopStep.PROCEED -> Unit
                    }
                }

                // Healthy (or network unusable)
                if (seamlessRecoveryAttempted != 0) {
                    log.i {
                        "Recovery episode ended for tunnel $tunnelId (attempts=$seamlessRecoveryAttempted)"
                    }
                }
                seamlessRecoveryAttempted = 0
                exhausted = false
                fastSettle = false
                ipv6FallbackTried = false
            }
        }
    }

    private suspend fun tryDynamicDnsRecovery(snap: Snapshot) {
        log.i { "DDNS  Recovery: attempting dynamic DNS recovery for tunnel $tunnelId" }
        val freshBootstrapResolution =
            host.resolveFresh()
                ?: run {
                    log.w { "DDNS Recovery: DNS resolution failed for peers" }
                    return
                }

        val activeConfig = host.getActiveConfig() ?: return

        // Preserve last good IPv4 address across an IPv6 only response window when the
        // network cannot use IPv6
        val previous =
            snap.lastResolvedPeers?.let { BootstrapResolution(it, resolvedTunnelDnsConfig = null) }
        val merged = freshBootstrapResolution.mergeWith(previous, snap.networkIpv6)

        // If peers are already on IPv6 but this network has no IPv6, ForceIpv4
        val familyOverride = ddnsRecoveryFamily(snap.networkIpv6, activeConfig.hasIpv6Peers())

        val mismatches =
            activeConfig.findEndpointMismatches(
                merged.peerKeyResults,
                familyOverride,
                networkIpv6 = snap.networkIpv6,
            )

        // Always refresh the cache as merged so a later ForceIpv4 path still sees IPv4 records
        host.updateActiveTunnel { it.copy(lastBootstrapResolution = merged) }

        if (mismatches.isEmpty()) {
            log.w {
                "DDNS Recovery: no endpoint IP change detected " +
                    "(family=$familyOverride networkIpv6=${snap.networkIpv6})"
            }
            return
        }

        val resolved = mode.config.buildResolvedPeers(mismatches)

        log.i {
            "DDNS Recovery: Found new IPs for peers (family=$familyOverride), " +
                "updating tunnel with new endpoints..."
        }

        host.updatePeers(resolved)
        host.emit(TunnelEvent.DynamicDnsUpdate(tunnelId, mismatches.keys.toList()))
    }

    @OptIn(ExperimentalAtomicApi::class)
    private suspend fun tryLightIpv4Fallback(snap: Snapshot) {
        // Not latched, so the fallback runs on a later pass once the reading is known
        if (snap.networkIpv6 == Ipv6Support.Unknown) {
            log.d { "Ipv4 Fallback: network IPv6 unknown, keeping peers for tunnel $tunnelId" }
            return
        }
        val activeConfig = host.getActiveConfig() ?: return
        if (!activeConfig.hasIpv6Peers()) return

        var dns = snap.lastResolvedPeers
        var mismatches =
            if (!dns.isNullOrEmpty()) {
                activeConfig.findEndpointMismatches(
                    dns,
                    FamilyOverride.ForceIpv4,
                    networkIpv6 = snap.networkIpv6,
                )
            } else {
                emptyMap()
            }

        // Cache my have only IPv6 address. Fresh resolve
        if (mismatches.isEmpty()) {
            val fresh =
                host.resolveFresh()
                    ?: run {
                        log.d { "Ipv4 Fallback: no fresh DNS for tunnel $tunnelId" }
                        return
                    }
            val previous = dns?.let { BootstrapResolution(it, resolvedTunnelDnsConfig = null) }
            val merged = fresh.mergeWith(previous, snap.networkIpv6)
            host.updateActiveTunnel { it.copy(lastBootstrapResolution = merged) }
            dns = merged.peerKeyResults
            mismatches =
                activeConfig.findEndpointMismatches(
                    dns,
                    FamilyOverride.ForceIpv4,
                    networkIpv6 = snap.networkIpv6,
                )
        }

        if (mismatches.isEmpty()) {
            log.d { "Ipv4 Fallback: no IPv4 endpoints available for tunnel $tunnelId" }
            return
        }

        // Only pin the network after a real switch so recovery can run
        lastIpv4FallbackNetworkKey.store(snap.activeNetworkKey)
        log.i { "Ipv4 Fallback: performing IPv4 fallback peer update for tunnel $tunnelId" }
        val resolved = mode.config.buildResolvedPeers(mismatches)
        host.updatePeers(resolved)
        host.emit(TunnelEvent.FallbackToIpv4(tunnelId))
    }

    private sealed interface Ipv6FallbackResult {
        /** Nothing to check (no active config, DNS or IPv4 peer), so a later pass may retry. */
        data object NotChecked : Ipv6FallbackResult

        /** No IPv4 peer has an AAAA record to try. */
        data object NoIpv6Host : Ipv6FallbackResult

        data class Switched(val previousPeers: List<PeerSection>) : Ipv6FallbackResult
    }

    /**
     * Moves IPv4 peers that have an AAAA record to it, for servers whose IPv4 path is down while
     * IPv6 works. The caller restores [Ipv6FallbackResult.Switched.previousPeers] if IPv6 does not
     * answer either.
     */
    private suspend fun tryLightIpv6Fallback(snap: Snapshot): Ipv6FallbackResult {
        val activeConfig = host.getActiveConfig() ?: return Ipv6FallbackResult.NotChecked
        val ipv4Peers =
            activeConfig.peers
                .filter { it.endpoint != null && it.endpoint?.contains("[") == false }
                .map { it.publicKey }
                .toSet()
        if (ipv4Peers.isEmpty()) return Ipv6FallbackResult.NotChecked

        fun ipv6Hosts(dns: Map<PublicKey, DnsBootstrapResult>) =
            activeConfig
                .findEndpointMismatches(dns, FamilyOverride.PreferIpv6, Ipv6Support.Available)
                .filter { (key, resolved) -> key in ipv4Peers && resolved.host.startsWith("[") }

        var dns = snap.lastResolvedPeers
        var mismatches = dns?.let(::ipv6Hosts).orEmpty()

        // Cache may predate the AAAA, so resolve fresh
        if (mismatches.isEmpty()) {
            val fresh = host.resolveFresh() ?: return Ipv6FallbackResult.NotChecked
            val previous = dns?.let { BootstrapResolution(it, resolvedTunnelDnsConfig = null) }
            val merged = fresh.mergeWith(previous, snap.networkIpv6)
            host.updateActiveTunnel { it.copy(lastBootstrapResolution = merged) }
            dns = merged.peerKeyResults
            mismatches = ipv6Hosts(dns)
        }

        if (mismatches.isEmpty()) {
            log.d { "Ipv6 Fallback: no IPv6 endpoints available for tunnel $tunnelId" }
            return Ipv6FallbackResult.NoIpv6Host
        }

        log.i {
            "Ipv6 Fallback: IPv4 still failing, trying IPv6 for ${mismatches.size} peer(s) " +
                "of tunnel $tunnelId"
        }
        // From live endpoints so peers that are not switched keep their current address
        val live = mode.withEndpointsFrom(activeConfig).config
        host.updatePeers(live.buildResolvedPeers(mismatches))
        return Ipv6FallbackResult.Switched(previousPeers = live.peers)
    }

    // Full bounce now only does a fresh DNS request if tunnel is a DDNS tunnel.
    // NonCancellable so becoming Healthy mid-bounce cannot abort stop/start half-way.
    private suspend fun tryFullTunnelBounce(withFreshResolution: Boolean): Boolean =
        withContext(NonCancellable) {
            log.i {
                "Seamless Recovery: bouncing tunnel $tunnelId (with fresh DNS request=$withFreshResolution)"
            }
            val didBounce = host.bounce(withFreshResolution = withFreshResolution)
            if (didBounce) {
                host.updateActiveTunnel {
                    it.copy(
                        recoveryAttempts = it.recoveryAttempts + 1,
                        lastRecoveryAttemptMs = System.currentTimeMillis(),
                    )
                }
                host.emit(TunnelEvent.SeamlessRecoveryAttempted(tunnelId))
            }
            didBounce
        }

    @OptIn(ExperimentalAtomicApi::class)
    private fun isIpv6Recoverable(snap: Snapshot): Boolean {
        val key = snap.activeNetworkKey
        return snap.recovery.ipv6Recovery &&
            snap.transportHealthy &&
            snap.networkIpv6 == Ipv6Support.Available &&
            !snap.bootstrapPending &&
            key != null &&
            key != lastIpv6RecoveryNetworkKey.load()
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun ipv6SkipReason(snap: Snapshot): String? {
        if (!snap.recovery.ipv6Recovery) return "ipv6 recovery disabled"
        if (!snap.transportHealthy) return "not healthy"
        if (snap.bootstrapPending) return "bootstrap pending"
        if (snap.networkIpv6 != Ipv6Support.Available) {
            return "network ipv6 ${snap.networkIpv6}"
        }
        if (snap.activeNetworkKey == null) return "no network key"
        if (snap.activeNetworkKey == lastIpv6RecoveryNetworkKey.load()) {
            return "blocked: already attempted on ${snap.activeNetworkKey}"
        }
        return null
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun CoroutineScope.runIpv6EndpointRecoveryJob() {
        launch {
            val snapshots =
                host
                    .observe()
                    .stateIn(
                        scope = this,
                        started = SharingStarted.Eagerly,
                        initialValue =
                            Snapshot(
                                shouldArmFailureRecovery = false,
                                shouldKeepFailureRecoveryEpisode = false,
                                transportHealthy = false,
                                bootstrapPending = false,
                                lastResolvedPeers = null,
                                networkIpv6 = Ipv6Support.Unknown,
                                activeNetworkKey = null,
                                deviceAwake = false,
                            ),
                    )

            launch {
                snapshots.collect { snap ->
                    if (!snap.transportHealthy || snap.networkIpv6 != Ipv6Support.Available) {
                        return@collect
                    }
                    ipv6SkipReason(snap)?.let { reason ->
                        log.d { "IPv6 recovery: skip ($reason) for tunnel $tunnelId" }
                    }
                }
            }

            log.d { "IPv6 recovery watcher started for tunnel $tunnelId" }

            while (isActive) {
                val candidate = snapshots.first { isIpv6Recoverable(it) }
                log.d {
                    "IPv6 recovery: candidate network=${candidate.activeNetworkKey} " +
                        "for tunnel $tunnelId"
                }

                delay(stabilizeWindow)

                val snap = snapshots.value
                if (!isIpv6Recoverable(snap)) {
                    log.d { "IPv6 recovery: no longer a candidate after stabilize, waiting" }
                    continue
                }

                when (tryIpv6Upgrade(snap)) {
                    Ipv6UpgradeResult.Skipped -> continue
                    Ipv6UpgradeResult.AlreadyOnIpv6 -> {
                        val key = snap.activeNetworkKey
                        snapshots.first {
                            it.activeNetworkKey != key ||
                                !it.transportHealthy ||
                                !it.recovery.ipv6Recovery ||
                                it.bootstrapPending
                        }
                    }
                    Ipv6UpgradeResult.Attempted,
                    Ipv6UpgradeResult.Upgraded ->
                        lastIpv6RecoveryNetworkKey.store(snap.activeNetworkKey)
                }
            }
        }
    }

    private enum class Ipv6UpgradeResult {
        Skipped,
        AlreadyOnIpv6,
        Attempted,
        Upgraded,
    }

    @OptIn(ExperimentalAtomicApi::class)
    private suspend fun tryIpv6Upgrade(snap: Snapshot): Ipv6UpgradeResult {
        val activeConfig =
            host.getActiveConfig()
                ?: run {
                    log.d { "IPv6 recovery: no active config for tunnel $tunnelId" }
                    return Ipv6UpgradeResult.Skipped
                }

        var dns = snap.lastResolvedPeers
        var mismatches =
            if (!dns.isNullOrEmpty()) {
                activeConfig.findEndpointMismatches(
                    dns,
                    FamilyOverride.PreferIpv6,
                    networkIpv6 = Ipv6Support.Available,
                )
            } else {
                emptyMap()
            }

        // Cached bootstrap from a v4-only network may have no AAAA. Fresh
        // resolve is safe here: DDNS/seamless/ipv4 fallback only run while
        // unhealthy, and this job only runs while healthy.
        if (mismatches.isEmpty()) {
            val fresh =
                host.resolveFresh()
                    ?: run {
                        log.d { "IPv6 recovery: no IPv6 endpoints available for tunnel $tunnelId" }
                        return if (activeConfig.hasIpv6Peers()) {
                            Ipv6UpgradeResult.AlreadyOnIpv6
                        } else {
                            Ipv6UpgradeResult.Attempted
                        }
                    }
            val previous = dns?.let { BootstrapResolution(it, resolvedTunnelDnsConfig = null) }
            val merged = fresh.mergeWith(previous, Ipv6Support.Available)
            host.updateActiveTunnel { it.copy(lastBootstrapResolution = merged) }
            dns = merged.peerKeyResults
            mismatches =
                activeConfig.findEndpointMismatches(
                    dns,
                    FamilyOverride.PreferIpv6,
                    networkIpv6 = Ipv6Support.Available,
                )
        }

        if (mismatches.isEmpty()) {
            log.d {
                "IPv6 recovery: all upgradable peers already on the chosen IPv6 host " +
                    "(or no AAAA) for tunnel $tunnelId"
            }
            return if (activeConfig.hasIpv6Peers()) {
                Ipv6UpgradeResult.AlreadyOnIpv6
            } else {
                Ipv6UpgradeResult.Attempted
            }
        }

        val afterFallback = snap.activeNetworkKey == lastIpv4FallbackNetworkKey.load()
        log.i {
            "Ipv6 Recovery: tunnel $tunnelId upgrading ${mismatches.size} peer(s) to IPv6" +
                if (afterFallback) " (after IPv4 fallback on ${snap.activeNetworkKey})" else ""
        }
        // If this upgrade is bad, IPv4 fallback must be allowed to run again on this network.
        lastIpv4FallbackNetworkKey.store(null)
        val resolved = mode.config.buildResolvedPeers(mismatches)
        host.updatePeers(resolved)
        host.emit(TunnelEvent.RecoveredToIpv6(tunnelId))
        return Ipv6UpgradeResult.Upgraded
    }

    companion object {
        /** Quiet period after becoming unhealthy to give tunnel time to stabilize */
        const val TUNNEL_HEALTH_STABILIZE_WINDOW_MILLIS = 8_000L

        const val MAX_SEAMLESS_RECOVERY_RETRIES = 8

        /** Settle time after a wake or network change (radios and DHCP need a moment) */
        val WAKE_SETTLE = 5.seconds

        /** Quick settles need this long since the last bounce */
        val FAST_BOUNCE_COOLDOWN = 30.seconds

        /** How long a wake or network change still counts as recent */
        val FRESH_SIGNAL_WINDOW = 60.seconds

        /** Retry interval once the quick bounce attempts are used up */
        val EXHAUSTED_RETRY_INTERVAL = 5.minutes

        val IDLE_RECOVERY =
            Tunnel.Feature.Recovery(seamlessRecovery = false, dynamicDnsRecovery = false)
    }
}
