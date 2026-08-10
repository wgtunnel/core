package com.wgtunnel.backend.service

import com.wgtunnel.backend.DesktopVpnBackend
import com.wgtunnel.backend.Tunnel
import com.wgtunnel.backend.WireGuardTunnelEngine
import com.wgtunnel.parser.Config

internal object DesktopVpnRuntime : VpnRuntime {

    override suspend fun createTunInterface(
        tunnel: Tunnel,
        config: Config,
        fakeDns: Boolean,
    ) {
        // TODO integrate fakeDNS for desktop
        val interfaceName = WireGuardTunnelEngine.WGT_INTERFACE_PREFIX + "${tunnel.id}"
        DesktopVpnBackend.createInterface(interfaceName, config.asQuickString())
    }

    override fun detachVpnTunnelFd(): Int? = null

    override fun startHevSocks5Bridge(port: Int, password: String) {
        // no-op
    }

    override fun stopHevSocks5Bridge() {
        // no-op
    }
}
