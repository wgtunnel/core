package com.wgtunnel.backend

internal object ProxyBackend {
    external fun startProxy(
        ifName: String,
        config: String,
        uapiPath: String,
        bypass: Int,
        dnsConfigJson: String?,
    ): Int

    external fun updateProxyTunnelPeers(handle: Int, settings: String): Int

    external fun turnProxyTunnelOff(handle: Int)

    external fun getProxyConfig(handle: Int): String
}
