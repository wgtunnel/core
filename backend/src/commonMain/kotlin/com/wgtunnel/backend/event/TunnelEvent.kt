package com.wgtunnel.backend.event

import com.wgtunnel.backend.util.PublicKey

sealed interface TunnelEvent {
    data class DynamicDnsUpdate(val tunnelId: Int, val changedPeers: List<PublicKey>) : TunnelEvent

    data class FallbackToIpv4(val tunnelId: Int) : TunnelEvent

    data class RecoveredToIpv6(val tunnelId: Int) : TunnelEvent

    data class NoRootShellAccess(val tunnelId: Int) : TunnelEvent

    data class SeamlessRecoveryAttempted(val tunnelId: Int) : TunnelEvent
}