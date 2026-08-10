package com.wgtunnel.backend

import com.wgtunnel.backend.service.VpnRuntime
import com.wgtunnel.parser.Config

internal object DesktopVpnBackend {
    @JvmStatic external fun createInterface(iface: String, settings: String): Int
    @JvmStatic external fun destroyInterface(iface: String)
}