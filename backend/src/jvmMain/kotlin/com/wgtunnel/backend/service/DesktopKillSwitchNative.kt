package com.wgtunnel.backend.service

internal object DesktopKillSwitchNative {
    @JvmStatic external fun setKillSwitch(enabled: Int): Int

    @JvmStatic external fun getKillSwitchStatus(): Int

    @JvmStatic external fun setKillSwitchAllowedNetworks(cidrsCsv: String): Int

    @JvmStatic external fun getKillSwitchAllowedNetworksEnabled(): Int
}
