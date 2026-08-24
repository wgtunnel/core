package com.wgtunnel.backend.dns

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.model.BackendMode
import com.wgtunnel.backend.model.dns.BootstrapResolution
import com.wgtunnel.backend.model.dns.DnsBoostrapConfig
import com.wgtunnel.backend.model.dns.DnsBoostrapMode
import com.wgtunnel.backend.model.dns.DnsBootstrapResult
import com.wgtunnel.backend.model.dns.TunnelDnsConfig
import com.wgtunnel.backend.system.NetworkMonitor
import com.wgtunnel.backend.util.PublicKey
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive

internal class EndpointResolver(
    private val networkMonitor: NetworkMonitor,
    private val systemDns: SystemDnsResolver,
    private val getDnsMode: () -> DnsBoostrapMode,
    private val isKillSwitchEnabled: () -> Boolean,
    private val createCustomResolver: (DnsBoostrapConfig, bypassNeeded: Boolean) -> PeerResolver,
) {
    val log = Logger.withTag("EndpointResolver")

    suspend fun resolve(
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig? = null,
    ): BootstrapResolution = coroutineScope {
        val staticPeers = mode.config.peers.filter { it.isStaticallyConfigured }
        val peersToResolve = mode.config.peers.filter { !it.isStaticallyConfigured }
        val peerResults = mutableMapOf<PublicKey, DnsBootstrapResult>()
        val dnsNeedsResolve = tunnelDnsConfig?.needsResolve() == true
        var resolvedDns: TunnelDnsConfig? = if (dnsNeedsResolve) null else tunnelDnsConfig

        if (staticPeers.isNotEmpty()) {
            log.i { "Static IP peers (skip DNS): ${staticPeers.size}" }
            log.d {
                "Static IP peers: " +
                    staticPeers.joinToString { "${shortKey(it.publicKey)}=${it.endpoint}" }
            }
        }

        if (peersToResolve.isEmpty() && !dnsNeedsResolve) {
            log.i { "Bootstrap: nothing to resolve (all endpoints are static IPs)" }
            return@coroutineScope BootstrapResolution(emptyMap(), tunnelDnsConfig)
        }

        log.i {
            "Bootstrap resolve starting: mode=${mode::class.simpleName} " +
                "hosts=${peersToResolve.size} dnsNeedsResolve=$dnsNeedsResolve"
        }
        log.d { "Bootstrap hosts=${peersToResolve.map { it.endpoint }}" }

        // Wait for connectivity
        val state = networkMonitor.networkState.first { it?.hasNetwork() == true }
        log.d { "Network ready for bootstrap: $state" }

        var delayMs = 500L
        var attempt = 0
        while (isActive) {
            if (networkMonitor.networkState.value?.hasNetwork() != true) {
                delay(100.milliseconds)

                continue
            }

            val dnsMode = getDnsMode()
            val bypassNeeded = mode is BackendMode.Vpn || isKillSwitchEnabled()
            attempt++

            val resolver: PeerResolver =
                when (dnsMode) {
                    is DnsBoostrapMode.System -> systemDns
                    is DnsBoostrapMode.Custom -> createCustomResolver(dnsMode.config, bypassNeeded)
                }
            log.i {
                "Resolve attempt $attempt via ${dnsModeLabel(dnsMode)} " +
                    "bypass=$bypassNeeded (VPN/KS underlay)"
            }
            log.d { "Resolve attempt $attempt ${describeDnsMode(dnsMode)}" }

            var progressed = false

            // Peers
            for ((publicKey, _, endpoint) in peersToResolve) {
                if (peerResults.containsKey(publicKey)) continue
                val host = endpoint?.substringBeforeLast(":") ?: continue
                val result =
                    try {
                        resolver.resolve(host)
                    } catch (t: Exception) {
                        log.w(t) { "Peer resolve threw for ${shortKey(publicKey)}" }
                        log.d { "Peer resolve host=$host" }
                        DnsBootstrapResult()
                    }
                if (result.ipv4.isNotEmpty() || result.ipv6.isNotEmpty()) {
                    peerResults[publicKey] =
                        result.copy(
                            ipv6 = result.ipv6.map { if (it.startsWith("[")) it else "[$it]" }
                        )
                    log.i { "Resolved peer ${shortKey(publicKey)}" }
                    log.d {
                        "Resolved peer ${shortKey(publicKey)} $endpoint → " +
                            "v4=${result.ipv4} v6=${result.ipv6}"
                    }
                    progressed = true
                } else {
                    log.w { "No addresses yet for peer ${shortKey(publicKey)}" }
                    log.d { "No addresses yet host=$host" }
                }
            }

            if (dnsNeedsResolve && resolvedDns == null) {
                val host = tunnelDnsConfig.resolveHost()
                if (host != null) {
                    val result =
                        try {
                            resolver.resolve(host)
                        } catch (t: Exception) {
                            log.w(t) { "Tunnel DNS resolve threw" }
                            log.d { "Tunnel DNS resolve host=$host" }
                            DnsBootstrapResult()
                        }
                    if (result.ipv4.isNotEmpty() || result.ipv6.isNotEmpty()) {
                        resolvedDns = tunnelDnsConfig.withResolvedAddresses(result)
                        log.i { "Tunnel DNS upstream resolved" }
                        log.d { "Tunnel DNS upstream $host → v4=${result.ipv4} v6=${result.ipv6}" }
                        progressed = true
                    } else {
                        log.w { "No addresses yet for tunnel DNS host" }
                        log.d { "No addresses yet for tunnel DNS host=$host" }
                    }
                }
            }

            val peersDone =
                peersToResolve.isEmpty() ||
                    peerResults.keys.containsAll(peersToResolve.map { it.publicKey })
            val dnsDone = !dnsNeedsResolve || resolvedDns != null

            if (peersDone && dnsDone) {
                log.i {
                    "Bootstrap resolve complete (peers=${peerResults.size}, dns=${resolvedDns != null})"
                }
                return@coroutineScope BootstrapResolution(peerResults, resolvedDns)
            }

            if (!progressed) {
                log.d { "Bootstrap retry in ${delayMs}ms (attempt=$attempt)" }
                delay(delayMs.milliseconds)
                delayMs = (delayMs * 2).coerceAtMost(MAX_BACKOFF)
            } else {
                delayMs = 500L
            }
        }

        log.w { "Bootstrap resolve cancelled with peers=${peerResults.size}" }
        BootstrapResolution(peerResults, resolvedDns)
    }

    private fun dnsModeLabel(mode: DnsBoostrapMode): String =
        when (mode) {
            is DnsBoostrapMode.System -> "system/local underlay"
            is DnsBoostrapMode.Custom -> "custom protocol=${mode.config.protocol}"
        }

    private fun describeDnsMode(mode: DnsBoostrapMode): String =
        when (mode) {
            is DnsBoostrapMode.System -> "system/local underlay"
            is DnsBoostrapMode.Custom ->
                "custom protocol=${mode.config.protocol} upstream=${mode.config.upstream}"
        }

    private fun shortKey(key: PublicKey): String =
        if (key.length <= 10) key else "${key.take(4)}…${key.takeLast(4)}"

    companion object {
        private const val MAX_BACKOFF = 30_000L
    }
}
