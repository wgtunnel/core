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
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlin.time.Duration.Companion.milliseconds

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
        val peersToResolve = mode.config.peers.filter { !it.isStaticallyConfigured }
        val peerResults = mutableMapOf<PublicKey, DnsBootstrapResult>()
        val dnsNeedsResolve = tunnelDnsConfig?.needsResolve() == true
        var resolvedDns: TunnelDnsConfig? = if (dnsNeedsResolve) null else tunnelDnsConfig

        if (peersToResolve.isEmpty() && !dnsNeedsResolve) {
            return@coroutineScope BootstrapResolution(emptyMap(), tunnelDnsConfig)
        }

        // Wait for connectivity
        val state = networkMonitor.networkState.first { it?.hasNetwork() == true }

        var delayMs = 500L
        while (isActive) {
            if (networkMonitor.networkState.value?.hasNetwork() != true) {
                delay(100.milliseconds)

                continue
            }

            val dnsMode = getDnsMode()
            val bypassNeeded = mode is BackendMode.Vpn || isKillSwitchEnabled()

            val resolver: PeerResolver = when (dnsMode) {
                is DnsBoostrapMode.System -> systemDns
                is DnsBoostrapMode.Custom ->
                    createCustomResolver(dnsMode.config, bypassNeeded)
            }

            var progressed = false

            // Peers
            for ((publicKey, _, endpoint) in peersToResolve) {
                if (peerResults.containsKey(publicKey)) continue
                val host = endpoint?.substringBeforeLast(":") ?: continue
                val result = resolver.resolve(host)
                if (result.ipv4.isNotEmpty() || result.ipv6.isNotEmpty()) {
                    peerResults[publicKey] =
                        result.copy(
                            ipv6 = result.ipv6.map { if (it.startsWith("[")) it else "[$it]" }
                        )
                    progressed = true
                }
            }

            if (dnsNeedsResolve && resolvedDns == null) {
                val host = tunnelDnsConfig.resolveHost()
                if (host != null) {
                    val result = resolver.resolve(host)
                    if (result.ipv4.isNotEmpty() || result.ipv6.isNotEmpty()) {
                        resolvedDns = tunnelDnsConfig.withResolvedAddresses(result)
                        log.d { "Tunnel DNS upstream resolved: $host" }
                        progressed = true
                    }
                }
            }

            val peersDone =
                peersToResolve.isEmpty() ||
                        peerResults.keys.containsAll(peersToResolve.map { it.publicKey })
            val dnsDone = !dnsNeedsResolve || resolvedDns != null

            if (peersDone && dnsDone) {
                log.d {
                    "Bootstrap resolve complete (peers=${peerResults.size}, dns=${resolvedDns != null})"
                }
                return@coroutineScope BootstrapResolution(peerResults, resolvedDns)
            }

            if (!progressed) {
                delay(delayMs.milliseconds)
                delayMs = (delayMs * 2).coerceAtMost(MAX_BACKOFF)
            } else {
                delayMs = 500L
            }
        }

        BootstrapResolution(peerResults, resolvedDns)
    }

    companion object {
        private const val MAX_BACKOFF = 30_000L
    }
}