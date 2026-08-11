package com.wgtunnel.backend.features

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.Tunnel
import com.wgtunnel.backend.enums.FamilyOverride
import com.wgtunnel.backend.event.TunnelEvent
import com.wgtunnel.backend.model.BackendMode
import com.wgtunnel.backend.model.dns.BootstrapResolution
import com.wgtunnel.backend.model.dns.DnsBootstrapResult
import com.wgtunnel.backend.state.ActiveTunnel
import com.wgtunnel.backend.util.PublicKey
import com.wgtunnel.backend.util.buildResolvedPeers
import com.wgtunnel.backend.util.findEndpointMismatches
import com.wgtunnel.backend.util.hasIpv6Peers
import com.wgtunnel.parser.ActiveConfig
import com.wgtunnel.parser.PeerSection
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.time.Duration
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

internal class TunnelRecovery(
    private val tunnelId: Int,
    private val mode: BackendMode,
    private val recovery: Tunnel.Feature.Recovery,
    private val failureThreshold: Duration,
    private val stabilizeWindow: Duration,
    private val host: Host,
) {

    private val log = Logger.withTag("TunnelRecovery")

    @OptIn(ExperimentalAtomicApi::class)
    private var lastIpv4FallbackNetworkKey: AtomicReference<String?> = AtomicReference(null)

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
        val shouldRecoveryBeActive: Boolean,
        val lastResolvedPeers: Map<PublicKey, DnsBootstrapResult>?,
        val networkHasIpv6: Boolean,
        val activeNetworkKey: String?,
        val deviceAwake: Boolean,
    )

    fun start(scope: CoroutineScope): Job = scope.launch {
        with(recovery) {
            if (ipv4Fallback || seamlessRecovery || dynamicDnsRecovery) {
                launch { runFailureRecovery() }
            }
        }
        if (recovery.ipv6Recovery) {
            launch { runIpv6EndpointRecoveryJob() }
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun CoroutineScope.runFailureRecovery() {

        launch {
            host.observe().collectLatest { snap ->
                log.d { "Running with state $snap" }
                if (!snap.shouldRecoveryBeActive) return@collectLatest

                // gate
                if (
                    !recovery.dynamicDnsRecovery &&
                        !recovery.seamlessRecovery &&
                        !recovery.ipv4Fallback
                )
                    return@collectLatest

                var seamlessRecoveryAttempted = 0

                while (isActive) {

                    // wait for initial stabilization
                    delay(stabilizeWindow)

                    // try DDNS recovery first if tunnel is a DDNS tunnel
                    if (recovery.dynamicDnsRecovery) {
                        tryDynamicDnsRecovery()
                        delay(stabilizeWindow)
                    }

                    // try IPv4 fallback when applicable
                    if (
                        recovery.ipv4Fallback &&
                            snap.activeNetworkKey != null &&
                            snap.activeNetworkKey != lastIpv4FallbackNetworkKey.load()
                    ) {
                        tryLightIpv4Fallback(snap)
                        delay(stabilizeWindow)
                    }

                    // Still failing, we do a full tunnel bounce
                    if (
                        recovery.seamlessRecovery &&
                            snap.deviceAwake &&
                            seamlessRecoveryAttempted <= MAX_SEAMLESS_RECOVERY_RETRIES
                    ) {
                        // assumes failure threshold is always larger than stabilization window
                        delay(failureThreshold)
                        tryFullTunnelBounce()
                        seamlessRecoveryAttempted++
                        log.d {
                            "Tunnel tunnel bounce attempt $seamlessRecoveryAttempted of $MAX_SEAMLESS_RECOVERY_RETRIES"
                        }
                    }
                }
            }
        }
    }

    private suspend fun tryDynamicDnsRecovery() {
        log.i { "DDNS  Recovery: attempting dynamic DNS recovery for tunnel $tunnelId" }
        val freshBootstrapResolution =
            host.resolveFresh()
                ?: run {
                    log.w { "DDNS Recovery: DNS resolution failed for peers" }
                    return
                }

        val activeConfig = host.getActiveConfig() ?: return
        val mismatches =
            activeConfig.findEndpointMismatches(
                freshBootstrapResolution.peerKeyResults,
                FamilyOverride.MatchCurrent,
            )

        if (mismatches.isEmpty()) {
            log.w { "DDNS Recovery: no endpoint IP change detected" }
            return
        }

        val resolved = mode.config.buildResolvedPeers(mismatches)

        log.i { "DDNS Recovery: Found new IPs for peers, updating tunnel with new endpoints..." }

        host.updatePeers(resolved)

        // Update the cache
        host.updateActiveTunnel { it.copy(lastBootstrapResolution = freshBootstrapResolution) }
        host.emit(TunnelEvent.DynamicDnsUpdate(tunnelId, mismatches.keys.toList()))
    }

    @OptIn(ExperimentalAtomicApi::class)
    private suspend fun tryLightIpv4Fallback(snap: Snapshot) {
        val activeConfig = host.getActiveConfig() ?: return
        val hasIpv6Peers = activeConfig.hasIpv6Peers()

        // Always record the network key so we never retry light recovery again for this network
        lastIpv4FallbackNetworkKey.store(snap.activeNetworkKey)

        if (!hasIpv6Peers || snap.lastResolvedPeers.isNullOrEmpty()) return

        val mismatches =
            activeConfig.findEndpointMismatches(snap.lastResolvedPeers, FamilyOverride.ForceIpv4)

        if (mismatches.isEmpty()) return

        log.i { "Ipv4 Fallback: performing IPv4 fallback peer update for tunnel $tunnelId" }
        val resolved = mode.config.buildResolvedPeers(mismatches)
        host.updatePeers(resolved)
        host.emit(TunnelEvent.FallbackToIpv4(tunnelId))
    }

    // Full bounce now only does a fresh DNS request if tunnel is a DDNS tunnel
    private suspend fun tryFullTunnelBounce() {
        log.i {
            "Seamless Recovery: bouncing tunnel $tunnelId (with fresh DNS request=${recovery.dynamicDnsRecovery})"
        }
        val didBounce = host.bounce(withFreshResolution = recovery.dynamicDnsRecovery)
        if (didBounce) {
            host.updateActiveTunnel {
                it.copy(
                    recoveryAttempts = it.recoveryAttempts + 1,
                    lastRecoveryAttemptMs = System.currentTimeMillis(),
                )
            }
        }
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun isIpv6Recoverable(snap: Snapshot): Boolean {
        val key = snap.activeNetworkKey
        return snap.networkHasIpv6 &&
            // ipv6 recovery runs on the inverse condition of the failure recovery job
            !snap.shouldRecoveryBeActive &&
            key != null &&
            key != lastIpv4FallbackNetworkKey.load()
    }

    private fun CoroutineScope.runIpv6EndpointRecoveryJob() {
        launch {
            host.observe().collectLatest { snap ->
                if (!isIpv6Recoverable(snap)) return@collectLatest
                delay(stabilizeWindow)
                val activeConfig = host.getActiveConfig() ?: return@collectLatest
                if (activeConfig.hasIpv6Peers()) return@collectLatest

                if (snap.lastResolvedPeers.isNullOrEmpty()) return@collectLatest

                val mismatches =
                    activeConfig.findEndpointMismatches(
                        snap.lastResolvedPeers,
                        FamilyOverride.ForceIpv6,
                    )
                if (mismatches.isEmpty()) return@collectLatest

                log.i { "Ipv6 Recovery: tunnel $tunnelId upgrading to IPv6" }
                val resolved = mode.config.buildResolvedPeers(mismatches)
                host.updatePeers(resolved)
                host.emit(TunnelEvent.RecoveredToIpv6(tunnelId))
            }
        }
    }

    companion object {
        const val TUNNEL_FAILURE_THRESHOLD_MILLIS = 30_000L
        const val TUNNEL_HEALTH_STABILIZE_WINDOW_MILLIS = 12_000L
        const val MAX_SEAMLESS_RECOVERY_RETRIES = 8
    }
}
