package com.wgtunnel.backend

import com.wgtunnel.backend.model.BackendMode
import com.wgtunnel.backend.model.EngineStartResult
import com.wgtunnel.backend.model.dns.TunnelDnsConfig
import com.wgtunnel.parser.ActiveConfig
import com.wgtunnel.parser.Config
import com.wgtunnel.parser.PeerSection

internal interface TunnelEngine {
    suspend fun start(
        tunnelId: Int,
        handle: Int,
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig? = null,
        // A failed start normally destroys the VPN runtime. A bounce keeps it so a failure can't
        // take down the interface that protects the user.
        destroyRuntimeOnFailure: Boolean = true,
        outerConfig: Config? = null,
        strictSplitTunnel: Boolean = false,
    ): EngineStartResult

    suspend fun stop(handle: Int, mode: BackendMode)

    suspend fun updatePeers(handle: Int, mode: BackendMode, peers: List<PeerSection>)

    suspend fun getActiveConfig(handle: Int, mode: BackendMode): ActiveConfig?
}
