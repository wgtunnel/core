package com.wgtunnel.backend

import com.wgtunnel.backend.model.BackendMode
import com.wgtunnel.backend.model.EngineStartResult
import com.wgtunnel.backend.model.dns.TunnelDnsConfig
import com.wgtunnel.parser.ActiveConfig
import com.wgtunnel.parser.PeerSection

internal interface TunnelEngine {
    suspend fun start(
        tunnelId: Int,
        handle: Int,
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig? = null,
    ): EngineStartResult

    suspend fun stop(handle: Int, mode: BackendMode)

    suspend fun updatePeers(handle: Int, mode: BackendMode, peers: List<PeerSection>)

    suspend fun getActiveConfig(handle: Int, mode: BackendMode): ActiveConfig?
}
