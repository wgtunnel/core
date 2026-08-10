package com.wgtunnel.backend

import com.wgtunnel.backend.event.TunnelEvent
import com.wgtunnel.backend.model.BackendMode
import com.wgtunnel.backend.model.KillSwitchConfig
import com.wgtunnel.backend.model.dns.DnsBoostrapMode
import com.wgtunnel.backend.model.dns.TunnelDnsConfig
import com.wgtunnel.backend.state.BackendStatus
import kotlinx.coroutines.flow.Flow

interface Backend {

    val applicationProvider: ApplicationProvider

    suspend fun start(
        tunnel: Tunnel,
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig? = null,
    ): Result<Unit>

    suspend fun stop(id: Int): Result<Unit>

    suspend fun setKillSwitch(config: KillSwitchConfig): Result<Unit>

    suspend fun disableKillSwitch(): Result<Unit>

    suspend fun setBootstrapDnsMode(mode: DnsBoostrapMode)

    suspend fun stopAllActiveTunnels(): Result<Unit>

    suspend fun bounceTunnelDevice(tunnelId: Int, withFreshResolution: Boolean): Boolean

    val status: Flow<BackendStatus>

    val events: Flow<TunnelEvent>
}
