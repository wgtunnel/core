package com.wgtunnel.backend.autotunnel

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.autotunnel.WildcardMatcher.matchesWildcardList
import com.wgtunnel.backend.autotunnel.WildcardMatcher.toWildcardRegex

class AutoTunnelEngine {
    private val log = Logger.withTag("AutoTunnelEngine")

    fun evaluate(state: AutoTunnelSnapshot): AutoTunnelDecision {
        return when (val decision = decide(state)) {
            is InternalDecision.Sync -> {
                if (decision.start.isEmpty() && decision.stop.isEmpty()) {
                    AutoTunnelDecision.DoNothing
                } else {
                    AutoTunnelDecision.Sync(start = decision.start, stop = decision.stop)
                }
            }
            InternalDecision.None -> AutoTunnelDecision.DoNothing
            InternalDecision.StopDueToNoInternet -> AutoTunnelDecision.StopAllDueToNoInternet
        }
    }

    private fun decide(state: AutoTunnelSnapshot): InternalDecision {
        val network = state.network
        val policy = state.policy
        val activeTunnelIds = state.activeTunnelIds

        val isOnCaptivePortalWifi =
            network.type == AutoTunnelNetworkType.WIFI && network.captivePortal

        if (isOnCaptivePortalWifi && policy.disableTunnelOnCaptivePortal) {
            return if (activeTunnelIds.isNotEmpty()) {
                InternalDecision.Sync(start = emptySet(), stop = activeTunnelIds)
            } else {
                InternalDecision.None
            }
        }

        if (!network.hasUsableNetwork) {
            return if (policy.isStopOnNoInternetEnabled) {
                InternalDecision.StopDueToNoInternet
            } else {
                InternalDecision.None
            }
        }

        val desiredTunnels = resolveDesiredTunnels(state).map { it.id }.toSet()
        val toStart = desiredTunnels - activeTunnelIds
        val toStop = activeTunnelIds - desiredTunnels

        if (toStart.isEmpty() && toStop.isEmpty()) {
            return InternalDecision.None
        }

        return InternalDecision.Sync(start = toStart, stop = toStop)
    }

    private fun resolveDesiredTunnels(state: AutoTunnelSnapshot): List<AutoTunnelTunnel> {
        val network = state.network
        val policy = state.policy

        return when {
            network.type == AutoTunnelNetworkType.ETHERNET && policy.isTunnelOnEthernetEnabled ->
                listOfNotNull(
                    state.tunnels.firstOrNull { it.isEthernetTunnel } ?: defaultTunnel(state)
                )
            network.type == AutoTunnelNetworkType.CELLULAR && policy.isTunnelOnMobileDataEnabled ->
                listOfNotNull(
                    state.tunnels.firstOrNull { it.isMobileDataTunnel } ?: defaultTunnel(state)
                )
            network.type == AutoTunnelNetworkType.WIFI &&
                policy.isTunnelOnWifiEnabled &&
                !isWifiTrusted(state) -> findPreferredWifiTunnel(state)
            else -> emptyList()
        }
    }

    private fun findPreferredWifiTunnel(state: AutoTunnelSnapshot): List<AutoTunnelTunnel> {
        val network = state.network
        val wildcardsEnabled = state.policy.isWildcardsEnabled

        val exactBssidMatches =
            state.tunnels.filter { tunnel -> tunnel.tunnelBssids.contains(network.bssid) }
        if (exactBssidMatches.isNotEmpty()) {
            val firstMatch = exactBssidMatches.first()
            log.i { "Starting tunnel ${firstMatch.name} for exact BSSID match" }
            return listOf(firstMatch)
        }

        val exactSsidMatches =
            state.tunnels.filter { tunnel -> tunnel.tunnelNetworks.contains(network.ssid) }
        if (exactSsidMatches.isNotEmpty()) {
            val firstMatch = exactSsidMatches.first()
            log.i { "Starting tunnel ${firstMatch.name} for exact SSID match" }
            return listOf(firstMatch)
        }

        if (wildcardsEnabled) {
            val bestBssidMatch =
                findBestWildcardMatchStartTunnel(
                    tunnels = state.tunnels,
                    value = network.bssid,
                    getPatterns = { it.tunnelBssids },
                )
            if (bestBssidMatch != null) {
                log.i { "Starting tunnel ${bestBssidMatch.name} for BSSID wildcard match" }
                return listOf(bestBssidMatch)
            }
        }

        if (wildcardsEnabled) {
            val bestSsidMatch =
                findBestWildcardMatchStartTunnel(
                    tunnels = state.tunnels,
                    value = network.ssid,
                    getPatterns = { it.tunnelNetworks },
                )
            if (bestSsidMatch != null) {
                log.i { "Starting tunnel ${bestSsidMatch.name} for SSID wildcard match" }
                return listOf(bestSsidMatch)
            }
        }

        log.i { "No preferred tunnel match, starting the default or first tunnel" }
        return listOfNotNull(defaultTunnel(state))
    }

    private fun findBestWildcardMatchStartTunnel(
        tunnels: List<AutoTunnelTunnel>,
        value: String,
        getPatterns: (AutoTunnelTunnel) -> List<String>,
    ): AutoTunnelTunnel? {
        return tunnels
            .mapNotNull { tunnel ->
                val patterns = getPatterns(tunnel)
                if (!patterns.matchesWildcardList(value)) {
                    return@mapNotNull null
                }
                val longestMatchingPatternLength =
                    patterns
                        .filter { pattern ->
                            if (pattern.startsWith("!")) return@filter false
                            pattern.toWildcardRegex().matches(value)
                        }
                        .maxOfOrNull { it.length } ?: 0
                tunnel to longestMatchingPatternLength
            }
            .maxByOrNull { it.second }
            ?.first
    }

    private fun isWifiTrusted(state: AutoTunnelSnapshot): Boolean {
        val network = state.network
        val policy = state.policy
        val ssidTrusted =
            matchesTrusted(
                value = network.ssid,
                trustedList = policy.trustedNetworkSsids,
                wildcardsEnabled = policy.isWildcardsEnabled,
            )
        val bssidTrusted =
            matchesTrusted(
                value = network.bssid,
                trustedList = policy.trustedNetworkBssids,
                wildcardsEnabled = policy.isWildcardsEnabled,
            )
        return ssidTrusted || bssidTrusted
    }

    private fun matchesTrusted(
        value: String,
        trustedList: List<String>,
        wildcardsEnabled: Boolean,
    ): Boolean {
        if (trustedList.contains(value)) return true
        if (wildcardsEnabled && trustedList.matchesWildcardList(value)) return true
        return false
    }

    private fun defaultTunnel(state: AutoTunnelSnapshot): AutoTunnelTunnel? {
        return state.tunnels.firstOrNull { it.isPrimaryTunnel } ?: state.tunnels.firstOrNull()
    }

    private sealed interface InternalDecision {
        data class Sync(val start: Set<Long>, val stop: Set<Long>) : InternalDecision

        data object None : InternalDecision

        data object StopDueToNoInternet : InternalDecision
    }
}
