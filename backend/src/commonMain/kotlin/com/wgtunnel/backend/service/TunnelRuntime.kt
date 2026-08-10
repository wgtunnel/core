package com.wgtunnel.backend.service

interface TunnelRuntime {
    suspend fun shutdown()
}

object NoOpTunnelRuntime : TunnelRuntime {
    override suspend fun shutdown() = Unit
}