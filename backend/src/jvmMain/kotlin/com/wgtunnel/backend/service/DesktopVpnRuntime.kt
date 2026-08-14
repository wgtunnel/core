package com.wgtunnel.backend.service

import com.wgtunnel.backend.DesktopVpnBackend
import com.wgtunnel.backend.Tunnel
import com.wgtunnel.backend.WireGuardTunnelEngine
import com.wgtunnel.backend.exception.BackendException
import com.wgtunnel.parser.Config

internal object DesktopVpnRuntime : VpnRuntime {

    override suspend fun createTunInterface(
        tunnel: Tunnel,
        config: Config,
        fakeDns: Boolean,
    ) {
        // TODO integrate fakeDNS for desktop
        val interfaceName = WireGuardTunnelEngine.interfacePrefix() + "${tunnel.id}"
        val rc = DesktopVpnBackend.createInterface(interfaceName, config.asQuickString())
        if (rc < 0) {
            DesktopVpnBackend.destroyInterface(interfaceName)
            throw BackendException.InternalError(
                "Failed to create tun interface $interfaceName (native code $rc)"
            )
        }
    }

    override fun detachVpnTunnelFd(): Int? = null

    override fun startHevSocks5Bridge(port: Int, password: String) {
        // no-op
    }

    override fun stopHevSocks5Bridge() {
        // no-op
    }
}
