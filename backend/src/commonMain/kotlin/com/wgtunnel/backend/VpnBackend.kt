package com.wgtunnel.backend

internal object VpnBackend {
    external fun getConfig(handle: Int): String?

    external fun turnOff(handle: Int)

    external fun turnOn(
        handle: Int,
        ifName: String,
        tunFd: Int,
        settings: String,
        dnsConfigJson: String?,
        uapiPath: String,
    ): Int

    external fun updateTunnelPeers(handle: Int, settings: String): Int

    external fun version(): String
}
