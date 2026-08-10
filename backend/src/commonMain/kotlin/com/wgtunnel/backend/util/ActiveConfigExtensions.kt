package com.wgtunnel.backend.util

import com.wgtunnel.backend.enums.FamilyOverride
import com.wgtunnel.backend.model.dns.DnsBootstrapResult
import com.wgtunnel.backend.model.dns.ResolvedHost
import com.wgtunnel.parser.ActiveConfig

internal fun ActiveConfig.findEndpointMismatches(
    freshDns: Map<PublicKey, DnsBootstrapResult>,
    familyOverride: FamilyOverride = FamilyOverride.MatchCurrent,
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
                dns.selectHostForPeer(current.endpoint, familyOverride) ?: return@mapNotNull null
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
