package com.wgtunnel.backend.model.dns

import com.wgtunnel.backend.enums.FamilyOverride

data class DnsBootstrapResult(
    val ipv4: List<String> = emptyList(),
    val ipv6: List<String> = emptyList(),
) {
    /**
     * Pick an endpoint host for a peer.
     *
     * - [FamilyOverride.ForceIpv4] never crosses to IPv6 (Ipv4Only / explicit fallback).
     * - IPv6 candidates are omitted when [networkHasIpv6] is false so we do not pin a peer to an
     *   unreachable family (see wgtunnel/android#1416).
     * - Other modes keep cross-family fallback for DS-Lite / single-family DNS answers, but only
     *   using IPv6 when the network can use it.
     *
     * Returning null means "no usable new host" — callers should keep the current endpoint.
     */
    fun selectHostForPeer(
        currentEndpoint: String?,
        familyOverride: FamilyOverride,
        networkHasIpv6: Boolean = true,
    ): String? {
        val currentlyIpv6 = currentEndpoint?.contains("[") == true
        val preferIpv6 =
            when (familyOverride) {
                FamilyOverride.MatchCurrent -> currentlyIpv6
                FamilyOverride.ForceIpv4 -> false
                FamilyOverride.PreferIpv6 -> true
            }

        val ipv6Candidates = if (networkHasIpv6) ipv6 else emptyList()

        val host =
            when (familyOverride) {
                // Strict: Ipv4Only and light IPv4 fallback must not adopt AAAA.
                FamilyOverride.ForceIpv4 -> ipv4.firstOrNull()
                else ->
                    if (preferIpv6) {
                        ipv6Candidates.firstOrNull() ?: ipv4.firstOrNull()
                    } else {
                        ipv4.firstOrNull() ?: ipv6Candidates.firstOrNull()
                    }
            } ?: return null

        return if (host.contains(":") && !host.startsWith("[")) "[$host]" else host
    }

    /**
     * Merge a fresh answer with a previous one. When the network cannot use IPv6, keep the last
     * known A records across a transient AAAA-only window so recovery still has a v4 candidate.
     * When the network has IPv6, empty A is accepted (server may be IPv6-only).
     */
    fun mergeWith(previous: DnsBootstrapResult?, networkHasIpv6: Boolean): DnsBootstrapResult {
        if (previous == null) return this
        val mergedV4 =
            when {
                ipv4.isNotEmpty() -> ipv4
                !networkHasIpv6 -> previous.ipv4
                else -> emptyList()
            }
        val mergedV6 = ipv6.ifEmpty { previous.ipv6 }
        return DnsBootstrapResult(ipv4 = mergedV4, ipv6 = mergedV6)
    }
}
