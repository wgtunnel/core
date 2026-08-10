package com.wgtunnel.backend.service

import com.wgtunnel.backend.ApplicationProvider
import com.wgtunnel.backend.DesktopVpnBackend
import com.wgtunnel.backend.Tunnel
import com.wgtunnel.backend.model.KillSwitchConfig
import com.wgtunnel.parser.Config

actual class RuntimeManager actual constructor(applicationProvider: ApplicationProvider) {

    actual val uapiPath = "/run/wgtunnel"

    actual val vpnUsesOsTunFd: Boolean
        get() = false
    actual suspend fun ensureVpnReady(): VpnRuntime {
        return DesktopVpnRuntime
    }

    actual suspend fun getTunnelService(): TunnelRuntime {
        return NoOpTunnelRuntime
    }

    actual suspend fun stopVpnService() {

    }

    actual suspend fun stopTunnelService() {
        // no-op
    }

    actual suspend fun stopCompanionService() {
        // no-op
    }

    actual suspend fun ensureVpnShutdown() {
        //TODO
    }

    actual suspend fun setKillSwitch(config: KillSwitchConfig?) {
        if(config == null) {
            DesktopKillSwitchNative.setKillSwitch(0)
        } else {
            DesktopKillSwitchNative.setKillSwitch(1)
            val csv = config.allowedIps.joinToString(",") { it.trim() }.trim()
            DesktopKillSwitchNative.setKillSwitchAllowedNetworks(csv)
        }

    }
    actual suspend fun isKillSwitchEnabled(): Boolean {
        val status = DesktopKillSwitchNative.getKillSwitchStatus()
        return status == 1
    }
}