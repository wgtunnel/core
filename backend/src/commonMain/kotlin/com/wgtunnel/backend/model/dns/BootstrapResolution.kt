package com.wgtunnel.backend.model.dns

import com.wgtunnel.backend.enums.FamilyOverride
import com.wgtunnel.backend.util.DnsHostUtils
import com.wgtunnel.backend.util.PublicKey

data class BootstrapResolution(
    val peerKeyResults: Map<PublicKey, DnsBootstrapResult>,
    val resolvedTunnelDnsConfig: TunnelDnsConfig?,
) {
    fun toHostMap(
        currentEndpoints: Map<PublicKey, String?> = emptyMap(),
        familyOverride: FamilyOverride = FamilyOverride.MatchCurrent,
        networkHasIpv6: Boolean = true,
    ): Map<PublicKey, ResolvedHost> =
        peerKeyResults
            .mapNotNull { (pubKey, result) ->
                // Prefer IP4P if present
                val ip4p = result.ipv6.firstNotNullOfOrNull { DnsHostUtils.decodeIp4p(it) }
                if (ip4p != null) {
                    val (ipv4, port) = ip4p
                    return@mapNotNull pubKey to ResolvedHost(host = ipv4, forcedPort = port)
                }

                val host =
                    result.selectHostForPeer(
                        currentEndpoints[pubKey],
                        familyOverride,
                        networkHasIpv6,
                    ) ?: return@mapNotNull null
                pubKey to ResolvedHost(host = host)
            }
            .toMap()

    /** Merge peer DNS results with a previous resolution. */
    fun mergeWith(previous: BootstrapResolution?, networkHasIpv6: Boolean): BootstrapResolution {
        if (previous == null) return this
        val keys = peerKeyResults.keys + previous.peerKeyResults.keys
        val mergedPeers = keys.associateWith { key ->
            val fresh = peerKeyResults[key]
            val prev = previous.peerKeyResults[key]
            when {
                fresh != null -> fresh.mergeWith(prev, networkHasIpv6)
                prev != null -> prev
                else -> DnsBootstrapResult()
            }
        }
        return BootstrapResolution(
            peerKeyResults = mergedPeers,
            resolvedTunnelDnsConfig = resolvedTunnelDnsConfig ?: previous.resolvedTunnelDnsConfig,
        )
    }
}
