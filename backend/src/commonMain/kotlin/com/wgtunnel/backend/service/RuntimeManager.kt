package com.wgtunnel.backend.service

import com.wgtunnel.backend.ApplicationProvider
import com.wgtunnel.backend.model.KillSwitchConfig

expect class RuntimeManager(applicationProvider: ApplicationProvider) {
    suspend fun getOrCreateVpnRuntime(): VpnRuntime

    suspend fun getOrCreateTunnelRuntime(): TunnelRuntime

    suspend fun destroyTunnelRuntime()

    suspend fun destroyVpnRuntime(tunnelIds: List<Int>)

    // null to disable
    suspend fun setKillSwitch(config: KillSwitchConfig?)

    suspend fun isKillSwitchEnabled(): Boolean

    val vpnUsesOsTunFd: Boolean
    val uapiPath: String
}
