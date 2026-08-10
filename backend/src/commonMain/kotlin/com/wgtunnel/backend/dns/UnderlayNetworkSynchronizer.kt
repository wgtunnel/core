package com.wgtunnel.backend.dns

import com.wgtunnel.backend.system.NetworkMonitor
import kotlinx.coroutines.CoroutineScope

expect class UnderlayNetworkSynchronizer(networkMonitor: NetworkMonitor, scope: CoroutineScope)