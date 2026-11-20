package com.wgtunnel.backend.service

import com.wgtunnel.backend.Tunnel
import com.wgtunnel.parser.Config

interface VpnRuntime {
    suspend fun createTunInterface(tunnel: Tunnel, config: Config, fakeDns: Boolean)

    fun detachVpnTunnelFd(): Int?

    fun startHevSocks5Bridge(port: Int, password: String)

    fun stopHevSocks5Bridge()

    // Windows only
    // Applies config's peers to the running tunnel, reopens its sockets and starts new
    // handshakes without recreating the tun adapter. False when the platform does not support it, or
    // it failed.
    suspend fun refreshInPlace(handle: Int, config: Config): Boolean = false

    companion object {
        const val HEV_BRIDGE_TRAFFIC_TAG = 0xF00D
    }
}
