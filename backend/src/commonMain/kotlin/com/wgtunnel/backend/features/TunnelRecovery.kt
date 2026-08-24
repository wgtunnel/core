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
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

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
        val networkHasIpv6: Boolean,
        val activeNetworkKey: String?,
        val deviceAwake: Boolean,
        val recovery: Tunnel.Feature.Recovery = IDLE_RECOVERY,
    )

    fun start(scope: CoroutineScope): Job = scope.launch {
        launch { runFailureRecovery() }
        launch { runIpv6EndpointRecoveryJob() }
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun CoroutineScope.runFailureRecovery() {
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
                                networkHasIpv6 = false,
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
                                "bounceDelay=${rec.bounceDelaySeconds}s"
                        }
                    }
            }

            var seamlessRecoveryAttempted = 0
            // Track idle to active so leaving Doze refreshes the bounce counter as it is a common
            // source of tunnel failures
            var wasDeviceAwake = snapshots.value.deviceAwake

            fun noteDeviceAwake(snap: Snapshot) {
                if (snap.deviceAwake && !wasDeviceAwake) {
                    if (seamlessRecoveryAttempted != 0) {
                        log.d {
                            "Recovery: left device idle, resetting bounce attempts for tunnel $tunnelId (was $seamlessRecoveryAttempted)"
                        }
                    }
                    seamlessRecoveryAttempted = 0
                }
                wasDeviceAwake = snap.deviceAwake
            }

            while (isActive) {
                // Arm only on HandshakeFailure — not Starting/unknown
                snapshots.first { it.shouldArmFailureRecovery }
                log.i { "Recovery episode started for tunnel $tunnelId" }
                noteDeviceAwake(snapshots.value)

                // Stay until Healthy (or network unusable), including bounce Down/Starting
                while (isActive && snapshots.value.shouldKeepFailureRecoveryEpisode) {
                    noteDeviceAwake(snapshots.value)

                    // Bootstrap in flight, wait until it is completed while keeping the session
                    // active
                    if (snapshots.value.bootstrapPending) {
                        log.d { "Recovery: waiting for bootstrap to finish for tunnel $tunnelId" }
                        snapshots.first {
                            !it.bootstrapPending || !it.shouldKeepFailureRecoveryEpisode
                        }
                        noteDeviceAwake(snapshots.value)
                        if (!snapshots.value.shouldKeepFailureRecoveryEpisode) break
                        // Bootstrap finished while still unhealthy, fall through to a fresh
                        // stabilize window before we act
                    }

                    val rec = snapshots.value.recovery
                    val willTryIpv4 =
                        rec.ipv4Fallback &&
                            snapshots.value.activeNetworkKey != null &&
                            snapshots.value.activeNetworkKey != lastIpv4FallbackNetworkKey.load()

                    if (rec.dynamicDnsRecovery || willTryIpv4) {
                        delay(stabilizeWindow)

                        noteDeviceAwake(snapshots.value)
                        if (!snapshots.value.shouldKeepFailureRecoveryEpisode) break
                        if (snapshots.value.bootstrapPending) continue

                        if (snapshots.value.recovery.dynamicDnsRecovery) {
                            tryDynamicDnsRecovery(snapshots.value)
                            delay(stabilizeWindow)
                            noteDeviceAwake(snapshots.value)
                            if (!snapshots.value.shouldKeepFailureRecoveryEpisode) break
                            if (snapshots.value.bootstrapPending) continue
                        }

                        val snap = snapshots.value
                        if (
                            snap.recovery.ipv4Fallback &&
                                snap.activeNetworkKey != null &&
                                snap.activeNetworkKey != lastIpv4FallbackNetworkKey.load()
                        ) {
                            tryLightIpv4Fallback(snap)
                            delay(stabilizeWindow)
                            noteDeviceAwake(snapshots.value)
                            if (!snapshots.value.shouldKeepFailureRecoveryEpisode) break
                            if (snapshots.value.bootstrapPending) continue
                        }
                    }

                    val beforeBounce = snapshots.value
                    noteDeviceAwake(beforeBounce)
                    if (
                        beforeBounce.recovery.seamlessRecovery &&
                            beforeBounce.deviceAwake &&
                            !beforeBounce.bootstrapPending &&
                            seamlessRecoveryAttempted < MAX_SEAMLESS_RECOVERY_RETRIES
                    ) {
                        delay(beforeBounce.recovery.bounceDelaySeconds.seconds)
                        val ready = snapshots.value
                        noteDeviceAwake(ready)
                        if (!ready.shouldKeepFailureRecoveryEpisode) break
                        // No full bounce while in Doze or when bootstrap is in flight
                        if (!ready.deviceAwake || ready.bootstrapPending) continue
                        if (!ready.recovery.seamlessRecovery) continue

                        tryFullTunnelBounce(ready.recovery.dynamicDnsRecovery)
                        seamlessRecoveryAttempted++
                        log.i {
                            "Tunnel bounce attempt $seamlessRecoveryAttempted of $MAX_SEAMLESS_RECOVERY_RETRIES"
                        }
                    } else {
                        // Seamless disabled, in Doze, bootstrap pending, or max retries
                        delay(stabilizeWindow)
                    }
                }

                // Healthy (or network unusable)
                if (seamlessRecoveryAttempted != 0) {
                    log.i {
                        "Recovery episode ended for tunnel $tunnelId (attempts=$seamlessRecoveryAttempted)"
                    }
                }
                seamlessRecoveryAttempted = 0
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
        val merged = freshBootstrapResolution.mergeWith(previous, snap.networkHasIpv6)

        // If peers are already on IPv6 but this network has no IPv6, ForceIpv4
        val familyOverride =
            if (!snap.networkHasIpv6 && activeConfig.hasIpv6Peers()) {
                FamilyOverride.ForceIpv4
            } else {
                FamilyOverride.MatchCurrent
            }

        val mismatches =
            activeConfig.findEndpointMismatches(
                merged.peerKeyResults,
                familyOverride,
                networkHasIpv6 = snap.networkHasIpv6,
            )

        // Always refresh the cache as merged so a later ForceIpv4 path still sees IPv4 records
        host.updateActiveTunnel { it.copy(lastBootstrapResolution = merged) }

        if (mismatches.isEmpty()) {
            log.w {
                "DDNS Recovery: no endpoint IP change detected " +
                    "(family=$familyOverride networkHasIpv6=${snap.networkHasIpv6})"
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
        val activeConfig = host.getActiveConfig() ?: return
        if (!activeConfig.hasIpv6Peers()) return

        var dns = snap.lastResolvedPeers
        var mismatches =
            if (!dns.isNullOrEmpty()) {
                activeConfig.findEndpointMismatches(
                    dns,
                    FamilyOverride.ForceIpv4,
                    networkHasIpv6 = snap.networkHasIpv6,
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
            val merged = fresh.mergeWith(previous, snap.networkHasIpv6)
            host.updateActiveTunnel { it.copy(lastBootstrapResolution = merged) }
            dns = merged.peerKeyResults
            mismatches =
                activeConfig.findEndpointMismatches(
                    dns,
                    FamilyOverride.ForceIpv4,
                    networkHasIpv6 = snap.networkHasIpv6,
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

    // Full bounce now only does a fresh DNS request if tunnel is a DDNS tunnel.
    // NonCancellable so becoming Healthy mid-bounce cannot abort stop/start half-way.
    private suspend fun tryFullTunnelBounce(withFreshResolution: Boolean) =
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
        }

    @OptIn(ExperimentalAtomicApi::class)
    private fun isIpv6Recoverable(snap: Snapshot): Boolean {
        val key = snap.activeNetworkKey
        return snap.recovery.ipv6Recovery &&
            snap.transportHealthy &&
            snap.networkHasIpv6 &&
            !snap.bootstrapPending &&
            key != null &&
            key != lastIpv6RecoveryNetworkKey.load()
    }

    @OptIn(ExperimentalAtomicApi::class)
    private fun ipv6SkipReason(snap: Snapshot): String? {
        if (!snap.recovery.ipv6Recovery) return "ipv6 recovery disabled"
        if (!snap.transportHealthy) return "not healthy"
        if (snap.bootstrapPending) return "bootstrap pending"
        if (!snap.networkHasIpv6) return "network has no ipv6"
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
                                networkHasIpv6 = false,
                                activeNetworkKey = null,
                                deviceAwake = false,
                            ),
                    )

            launch {
                snapshots.collect { snap ->
                    if (!snap.transportHealthy || !snap.networkHasIpv6) return@collect
                    ipv6SkipReason(snap)?.let { reason ->
                        log.d { "IPv6 recovery: skip ($reason) for tunnel $tunnelId" }
                    }
                }
            }

            log.i { "IPv6 recovery watcher started for tunnel $tunnelId" }

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
                    networkHasIpv6 = true,
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
            val merged = fresh.mergeWith(previous, networkHasIpv6 = true)
            host.updateActiveTunnel { it.copy(lastBootstrapResolution = merged) }
            dns = merged.peerKeyResults
            mismatches =
                activeConfig.findEndpointMismatches(
                    dns,
                    FamilyOverride.PreferIpv6,
                    networkHasIpv6 = true,
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

        val IDLE_RECOVERY =
            Tunnel.Feature.Recovery(seamlessRecovery = false, dynamicDnsRecovery = false)
    }
}
