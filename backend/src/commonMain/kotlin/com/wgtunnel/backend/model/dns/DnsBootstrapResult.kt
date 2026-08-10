package com.wgtunnel.backend.model.dns

import com.wgtunnel.backend.enums.FamilyOverride

data class DnsBootstrapResult(
    val ipv4: List<String> = emptyList(),
    val ipv6: List<String> = emptyList(),
) {
    fun selectHostForPeer(
        currentEndpoint: String?,
        familyOverride: FamilyOverride,
    ): String? {
        val currentlyIpv6 = currentEndpoint?.contains("[") == true
        val preferIpv6 =
            when (familyOverride) {
                FamilyOverride.MatchCurrent -> currentlyIpv6
                FamilyOverride.ForceIpv4 -> false
                FamilyOverride.ForceIpv6 -> true
            }
        val host =
            if (preferIpv6) {
                ipv6.firstOrNull() ?: ipv4.firstOrNull()
            } else {
                ipv4.firstOrNull() ?: ipv6.firstOrNull()
            } ?: return null

        return if (host.contains(":") && !host.startsWith("[")) "[$host]" else host
    }
}