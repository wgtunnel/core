package com.wgtunnel.backend.dns

import com.wgtunnel.backend.system.NetworkMonitor
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.distinctUntilChangedBy
import kotlinx.coroutines.launch

actual class UnderlayNetworkSynchronizer actual constructor(networkMonitor: NetworkMonitor, scope: CoroutineScope) {
    init {
        scope.launch {
            networkMonitor.networkState.distinctUntilChangedBy { it?.key }.collect {
                val network = it?.network
                UnderlayDnsBridge.setUnderlayNetwork(network)
            }
        }
    }
}