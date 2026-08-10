package com.wgtunnel.backend.state

import com.wgtunnel.backend.model.BackendMode
import com.wgtunnel.backend.model.dns.DnsBoostrapMode

data class BackendStatus(
    val killSwitch: KillSwitchState = KillSwitchState(),
    val activeTunnels: Map<Int, ActiveTunnel> = emptyMap(),
    val dnsMode: DnsBoostrapMode = DnsBoostrapMode.System,
) {
    fun toNotificationComparisonKey(): Any =
        activeTunnels.mapValues { (_, tunnel) ->
            Triple(
                tunnel.transportState,
                tunnel.bootstrapState,
                tunnel.mode is BackendMode.Vpn || tunnel.mode is BackendMode.Proxy.KillSwitchPrimary,
            )
        } to (activeTunnels.keys to (killSwitch.enabled to dnsMode))
}