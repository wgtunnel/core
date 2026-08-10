package com.wgtunnel.backend.service

import com.wgtunnel.backend.ApplicationProvider
import com.wgtunnel.backend.model.KillSwitchConfig

expect class RuntimeManager(applicationProvider: ApplicationProvider) {
    suspend fun ensureVpnReady(): VpnRuntime
    suspend fun getTunnelService(): TunnelRuntime
    suspend fun stopVpnService()
    suspend fun stopTunnelService()
    suspend fun stopCompanionService()
    suspend fun ensureVpnShutdown()

    // null to disable
    suspend fun setKillSwitch(config: KillSwitchConfig?)

    suspend fun isKillSwitchEnabled() : Boolean

    val vpnUsesOsTunFd : Boolean
    val uapiPath: String
}