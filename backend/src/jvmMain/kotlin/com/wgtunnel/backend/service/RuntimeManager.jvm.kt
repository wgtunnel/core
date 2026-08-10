package com.wgtunnel.backend.service

import com.wgtunnel.backend.ApplicationProvider
import com.wgtunnel.backend.DesktopVpnBackend
import com.wgtunnel.backend.WireGuardTunnelEngine
import com.wgtunnel.backend.model.KillSwitchConfig

actual class RuntimeManager actual constructor(applicationProvider: ApplicationProvider) {

    actual val uapiPath = "/run/wgtunnel"

    actual val vpnUsesOsTunFd: Boolean
        get() = false

    actual suspend fun getOrCreateVpnRuntime(): VpnRuntime {
        return DesktopVpnRuntime
    }

    actual suspend fun getOrCreateTunnelRuntime(): TunnelRuntime {
        return NoOpTunnelRuntime
    }

    actual suspend fun destroyTunnelRuntime() {
        // no-op
    }

    actual suspend fun destroyVpnRuntime(tunnelIds: List<Int>) {
        tunnelIds.forEach { id ->
            val interfaceName = WireGuardTunnelEngine.WGT_INTERFACE_PREFIX + "$id"
            DesktopVpnBackend.destroyInterface(interfaceName)
        }
    }

    actual suspend fun setKillSwitch(config: KillSwitchConfig?) {
        if (config == null) {
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
