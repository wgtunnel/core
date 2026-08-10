package com.wgtunnel.backend.dns

import com.wgtunnel.backend.system.NetworkMonitor
import kotlinx.coroutines.CoroutineScope

actual class UnderlayNetworkSynchronizer
actual constructor(networkMonitor: NetworkMonitor, scope: CoroutineScope) {
    // no-op, handled in native for desktop
}
