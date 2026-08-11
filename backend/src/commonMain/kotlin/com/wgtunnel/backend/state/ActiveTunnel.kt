package com.wgtunnel.backend.state

import com.wgtunnel.backend.Tunnel
import com.wgtunnel.backend.model.BackendMode
import com.wgtunnel.backend.model.dns.BootstrapResolution
import com.wgtunnel.backend.model.dns.TunnelDnsConfig
import com.wgtunnel.parser.ActiveConfig

data class ActiveTunnel(
    val tunnel: Tunnel? = null,
    val mode: BackendMode? = null,
    val transportState: Tunnel.State = Tunnel.State.Down,
    val bootstrapState: BootstrapState = BootstrapState.None,
    val lastHealthChangeMs: Long = 0L,
    val interfaceName: String? = null,
    val activeConfig: ActiveConfig? = null,
    val uptime: Long? = null,
    val recoveryAttempts: Int = 0,
    val lastRecoveryAttemptMs: Long = 0L,
    val tunnelDnsConfig: TunnelDnsConfig? = null,
    val lastBootstrapResolution: BootstrapResolution? = null,
) {
    fun getRuntimeTunnelDnsConfig(): TunnelDnsConfig? {
        return lastBootstrapResolution?.resolvedTunnelDnsConfig ?: tunnelDnsConfig
    }

    // helper to know if recovery job should remain active
    // We consider states that would be caused by an active bounce or failure as recovery should be
    // active
    fun shouldRecoveryBeActive(hasUsableNetwork: Boolean): Boolean {
        val hasRecoveryTransportState =
            when (transportState) {
                Tunnel.State.Down,
                Tunnel.State.Starting,
                Tunnel.State.Stopping,
                Tunnel.State.Up.HandshakeFailure -> true
                Tunnel.State.Up.Healthy -> false
            }
        return hasRecoveryTransportState &&
            bootstrapState !is BootstrapState.ResolvingDns &&
            hasUsableNetwork
    }
}
