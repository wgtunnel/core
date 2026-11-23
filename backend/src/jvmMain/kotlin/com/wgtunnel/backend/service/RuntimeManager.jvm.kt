package com.wgtunnel.backend.service

import com.wgtunnel.backend.ApplicationProvider
import com.wgtunnel.backend.DesktopApplicationProvider
import com.wgtunnel.backend.DesktopVpnBackend
import com.wgtunnel.backend.WireGuardTunnelEngine
import com.wgtunnel.backend.exception.BackendException
import com.wgtunnel.backend.model.KillSwitchConfig

actual class RuntimeManager actual constructor(applicationProvider: ApplicationProvider) {

    private val desktop = applicationProvider as DesktopApplicationProvider

    actual val uapiPath: String
        get() = desktop.uapiPath

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
            val interfaceName = WireGuardTunnelEngine.interfacePrefix() + "$id"
            DesktopVpnBackend.destroyInterface(interfaceName)
        }
    }

    actual suspend fun setKillSwitch(config: KillSwitchConfig?) {
        if (config == null) {
            val rc = DesktopKillSwitchNative.setKillSwitch(0)
            if (rc < 0) {
                throw BackendException.InternalError("Failed to disable kill switch (native code $rc)")
            }
            return
        }
        val rc = DesktopKillSwitchNative.setKillSwitch(1)
        if (rc < 0) {
            throw BackendException.InternalError("Failed to enable kill switch (native code $rc)")
        }
        val csv = config.allowedIps.joinToString(",") { it.trim() }.trim()
        val nets = DesktopKillSwitchNative.setKillSwitchAllowedNetworks(csv)
        // The kill switch stays on. Failing open here would drop protection over a LAN list.
        if (nets < 0) {
            throw BackendException.InternalError(
                "Failed to apply kill switch allowed networks (native code $nets)",
            )
        }
    }

    actual suspend fun isKillSwitchEnabled(): Boolean {
        val status = DesktopKillSwitchNative.getKillSwitchStatus()
        return status == 1
    }
}
