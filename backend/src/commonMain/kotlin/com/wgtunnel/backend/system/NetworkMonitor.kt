package com.wgtunnel.backend.system

import kotlinx.coroutines.flow.StateFlow

interface NetworkMonitor {
    val networkState: StateFlow<NetworkSnapshot?>
}
