package com.wgtunnel.backend.state

import com.wgtunnel.backend.model.KillSwitchConfig

data class KillSwitchState(
    val enabled: Boolean = false,
    val config: KillSwitchConfig? = null,
    val primaryTunnel: Long? = null,
)
