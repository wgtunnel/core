package com.wgtunnel.backend.model

data class KillSwitchConfig(
    val allowedIps: Set<String>,
    val metered: Boolean,
    val dualStack: Boolean,
)