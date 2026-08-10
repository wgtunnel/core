package com.wgtunnel.backend.service

import com.wgtunnel.backend.Tunnel
import com.wgtunnel.parser.Config

internal object DesktopVpnRuntime : VpnRuntime {
    override suspend fun createTunInterface(
        tunnel: Tunnel,
        config: Config,
        fakeDns: String?,
    ) {

    }

    override fun detachVpnTunnelFd(): Int? = null
}