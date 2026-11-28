package com.wgtunnel.backend

import com.wgtunnel.backend.event.TunnelEvent
import com.wgtunnel.backend.model.BackendMode
import com.wgtunnel.backend.model.KillSwitchConfig
import com.wgtunnel.backend.model.dns.DnsBoostrapMode
import com.wgtunnel.backend.model.dns.TunnelDnsConfig
import com.wgtunnel.backend.state.BackendStatus
import com.wgtunnel.parser.Config
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow

interface Backend {

    val applicationProvider: ApplicationProvider

    suspend fun start(
        tunnel: Tunnel,
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig? = null,
        outerConfig: Config? = null,
    ): Result<Unit>

    suspend fun stop(id: Int): Result<Unit>

    suspend fun setKillSwitch(config: KillSwitchConfig): Result<Unit>

    suspend fun disableKillSwitch(): Result<Unit>

    /**
     * Local networks reachable outside the tunnel whenever the desktop firewall blocks, for the
     * kill switch or a full tunnel. Empty blocks them. No effect on Android, where LAN access is
     * part of [KillSwitchConfig].
     */
    suspend fun setAllowedLocalNetworks(networks: Set<String>): Result<Unit>

    suspend fun setBootstrapDnsMode(mode: DnsBoostrapMode)

    suspend fun stopAllActiveTunnels(): Result<Unit>

    suspend fun bounceTunnelDevice(tunnelId: Int, withFreshResolution: Boolean): Boolean

    suspend fun updateTunnel(tunnel: Tunnel): Result<Unit>

    val status: StateFlow<BackendStatus>

    val events: Flow<TunnelEvent>
}
