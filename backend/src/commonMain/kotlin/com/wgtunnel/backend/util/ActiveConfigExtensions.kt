package com.wgtunnel.backend.util

import com.wgtunnel.backend.enums.FamilyOverride
import com.wgtunnel.backend.enums.Ipv6Support
import com.wgtunnel.backend.model.dns.DnsBootstrapResult
import com.wgtunnel.backend.model.dns.ResolvedHost
import com.wgtunnel.parser.ActiveConfig

internal fun ActiveConfig.findEndpointMismatches(
    freshDns: Map<PublicKey, DnsBootstrapResult>,
    familyOverride: FamilyOverride = FamilyOverride.MatchCurrent,
    networkIpv6: Ipv6Support = Ipv6Support.Available,
): Map<PublicKey, ResolvedHost> {
    val currentByKey = peers.associateBy { it.publicKey }
    return freshDns
        .mapNotNull { (pubKey, dns) ->
            val current = currentByKey[pubKey] ?: return@mapNotNull null
            val currentHost = current.host ?: return@mapNotNull null

            // Prefer IP4P when present
            val ip4p = dns.ipv6.firstNotNullOfOrNull { DnsHostUtils.decodeIp4p(it) }
            if (ip4p != null) {
                val (decodedIp, decodedPort) = ip4p
                return@mapNotNull if (decodedIp != currentHost) {
                    pubKey to ResolvedHost(host = decodedIp, forcedPort = decodedPort)
                } else {
                    null
                }
            }

            // Normal path
            val freshHost =
                dns.selectHostForPeer(current.endpoint, familyOverride, networkIpv6)
                    ?: return@mapNotNull null
            if (freshHost != currentHost) {
                pubKey to ResolvedHost(host = freshHost)
            } else {
                null
            }
        }
        .toMap()
}

fun ActiveConfig.hasIpv6Peers(): Boolean {
    return this.peers.any { it.endpoint?.contains("[") == true }
}

/** Whether any of [keys] has a live IPv6 endpoint. */
internal fun ActiveConfig.hasIpv6Peers(keys: Set<PublicKey>): Boolean {
    return this.peers.any { it.publicKey in keys && it.endpoint?.contains("[") == true }
}

internal fun ActiveConfig.hasIpv4Peers(): Boolean {
    return this.peers.any { it.endpoint != null && it.endpoint?.contains("[") == false }
}
