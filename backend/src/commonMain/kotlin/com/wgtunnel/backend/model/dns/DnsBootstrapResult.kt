package com.wgtunnel.backend.model.dns

import com.wgtunnel.backend.enums.FamilyOverride
import com.wgtunnel.backend.enums.Ipv6Support
import com.wgtunnel.backend.util.DnsHostUtils

data class DnsBootstrapResult(
    val ipv4: List<String> = emptyList(),
    val ipv6: List<String> = emptyList(),
) {
    /**
     * Pick an endpoint host for a peer.
     *
     * - [FamilyOverride.ForceIpv4] never crosses to IPv6 (Ipv4Only / explicit fallback).
     * - IPv6 candidates are omitted when [networkIpv6] is [Ipv6Support.Unavailable] so we do not
     *   pin a peer to an unreachable family (see wgtunnel/android#1416). [Ipv6Support.Unknown]
     *   keeps them, so a peer is not moved off IPv6 on a reading the monitor does not have yet.
     * - Other modes keep cross-family fallback for DS-Lite / single-family DNS answers.
     *
     * Returning null means "no usable new host" — callers should keep the current endpoint.
     */
    fun selectHostForPeer(
        currentEndpoint: String?,
        familyOverride: FamilyOverride,
        networkIpv6: Ipv6Support = Ipv6Support.Available,
    ): String? {
        val currentlyIpv6 = currentEndpoint?.contains("[") == true
        val preferIpv6 =
            when (familyOverride) {
                FamilyOverride.MatchCurrent -> currentlyIpv6
                FamilyOverride.ForceIpv4 -> false
                FamilyOverride.PreferIpv6 -> true
            }

        val ipv6Candidates = if (networkIpv6 == Ipv6Support.Unavailable) emptyList() else ipv6

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

        return bracketed(host)
    }

    /**
     * The only usable host of an AAAA-only answer. A peer that must be (re)started needs an IP, the
     * engine rejects a hostname endpoint.
     */
    fun ipv6OnlyHost(): String? = if (ipv4.isEmpty()) ipv6.firstOrNull()?.let(::bracketed) else null

    /**
     * Merge a fresh answer with a previous one. Unless the network is known to have IPv6, keep the
     * last known A records across a transient AAAA-only window so recovery still has a v4
     * candidate. When the network has IPv6, empty A is accepted (server may be IPv6-only).
     */
    fun mergeWith(previous: DnsBootstrapResult?, networkIpv6: Ipv6Support): DnsBootstrapResult {
        if (previous == null) return this
        val mergedV4 =
            when {
                ipv4.isNotEmpty() -> ipv4
                networkIpv6 != Ipv6Support.Available -> previous.ipv4
                else -> emptyList()
            }
        val mergedV6 = ipv6.ifEmpty { previous.ipv6 }
        return DnsBootstrapResult(ipv4 = mergedV4, ipv6 = mergedV6)
    }

    /**
     * Drops AAAA answers a DNS64 resolver synthesized from the A records. They reach the server's
     * IPv4 address through NAT64, so they must not win over the A record when IPv6 is preferred as
     * NAT64 often cannot hairpin to a server behind the same router.
     */
    fun withoutNat64Synthesized(): DnsBootstrapResult {
        if (ipv4.isEmpty()) return this
        val real = ipv6.filterNot(DnsHostUtils::isNat64Synthesized)
        return if (real.size == ipv6.size) this else copy(ipv6 = real)
    }

    private fun bracketed(host: String): String =
        if (host.contains(":") && !host.startsWith("[")) "[$host]" else host
}
