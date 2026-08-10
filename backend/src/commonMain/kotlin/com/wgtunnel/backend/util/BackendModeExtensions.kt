package com.wgtunnel.backend.util

import com.wgtunnel.backend.model.BackendMode
import com.wgtunnel.backend.model.dns.ResolvedHost
import com.wgtunnel.parser.ActiveConfig

internal fun BackendMode.rebuildModeWithHostMap(
    hostMap: Map<PublicKey, ResolvedHost>
): BackendMode {
    val resolvedPeers = config.buildResolvedPeers(hostMap)
    val resolvedConfig = config.copy(peers = resolvedPeers)
    return when (this) {
        is BackendMode.Vpn -> copy(config = resolvedConfig)
        is BackendMode.Proxy.Standard -> copy(config = resolvedConfig)
        is BackendMode.Proxy.KillSwitchPrimary -> copy(config = resolvedConfig)
    }
}

internal fun BackendMode.withEndpointsFrom(active: ActiveConfig): BackendMode {
    val endpointByKey = active.peers.associate { it.publicKey to it.endpoint }
    val updatedPeers =
        config.peers.map { peer ->
            val liveEndpoint = endpointByKey[peer.publicKey]
            if (liveEndpoint.isNullOrBlank()) peer else peer.copy(endpoint = liveEndpoint)
        }
    val resolvedConfig = config.copy(peers = updatedPeers)
    return when (this) {
        is BackendMode.Vpn -> copy(config = resolvedConfig)
        is BackendMode.Proxy.Standard -> copy(config = resolvedConfig)
        is BackendMode.Proxy.KillSwitchPrimary -> copy(config = resolvedConfig)
    }
}
