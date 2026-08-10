package com.wgtunnel.backend.model

data class EngineStartResult(
    val tunnelId: Int,
    val handle: Int,
    val interfaceName: String,
    val mode: BackendMode,
)
