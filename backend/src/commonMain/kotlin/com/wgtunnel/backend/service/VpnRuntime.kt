package com.wgtunnel.backend.service

import com.wgtunnel.backend.Tunnel
import com.wgtunnel.parser.Config

interface VpnRuntime {
    suspend fun createTunInterface(tunnel: Tunnel, config: Config, fakeDns: Boolean)

    fun detachVpnTunnelFd(): Int?

    fun startHevSocks5Bridge(port: Int, password: String)

    fun stopHevSocks5Bridge()

    companion object {
        const val HEV_BRIDGE_TRAFFIC_TAG = 0xF00D
    }
}
