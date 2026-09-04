package com.wgtunnel.backend.autotunnel

enum class AutoTunnelNetworkType {
    WIFI,
    ETHERNET,
    CELLULAR,
    DISCONNECTED,
}

data class AutoTunnelNetwork(
    val type: AutoTunnelNetworkType = AutoTunnelNetworkType.DISCONNECTED,
    val ssid: String = "",
    val bssid: String = "",
    val hasUsableNetwork: Boolean = false,
    val captivePortal: Boolean = false,
) {
    fun fingerprint(bssidAware: Boolean): String {
        return when (type) {
            AutoTunnelNetworkType.WIFI -> if (bssidAware) "wifi:$ssid:$bssid" else "wifi:$ssid"
            AutoTunnelNetworkType.ETHERNET -> "ethernet"
            AutoTunnelNetworkType.CELLULAR -> "cellular"
            AutoTunnelNetworkType.DISCONNECTED -> "none"
        }
    }
}

data class AutoTunnelPolicy(
    val isTunnelOnWifiEnabled: Boolean = false,
    val isTunnelOnEthernetEnabled: Boolean = false,
    val isTunnelOnMobileDataEnabled: Boolean = false,
    val isWildcardsEnabled: Boolean = false,
    val isStopOnNoInternetEnabled: Boolean = false,
    val disableTunnelOnCaptivePortal: Boolean = false,
    val trustedNetworkSsids: List<String> = emptyList(),
    val trustedNetworkBssids: List<String> = emptyList(),
)

data class AutoTunnelTunnel(
    val id: Long,
    val name: String,
    val isPrimaryTunnel: Boolean = false,
    val isEthernetTunnel: Boolean = false,
    val isMobileDataTunnel: Boolean = false,
    val tunnelNetworks: List<String> = emptyList(),
    val tunnelBssids: List<String> = emptyList(),
)

data class AutoTunnelSnapshot(
    val network: AutoTunnelNetwork = AutoTunnelNetwork(),
    val policy: AutoTunnelPolicy = AutoTunnelPolicy(),
    val tunnels: List<AutoTunnelTunnel> = emptyList(),
    val activeTunnelIds: Set<Long> = emptySet(),
)

sealed interface AutoTunnelDecision {
    data class Sync(val start: Set<Long>, val stop: Set<Long>) : AutoTunnelDecision

    data object DoNothing : AutoTunnelDecision

    data object StopAllDueToNoInternet : AutoTunnelDecision
}
