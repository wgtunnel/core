package com.wgtunnel.backend

internal object DesktopVpnBackend {
    @JvmStatic external fun createInterface(iface: String, settings: String): Int

    @JvmStatic external fun destroyInterface(iface: String)
}
