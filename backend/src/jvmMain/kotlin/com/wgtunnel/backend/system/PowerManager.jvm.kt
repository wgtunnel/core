package com.wgtunnel.backend.system

import com.wgtunnel.backend.ApplicationProvider
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf

actual class PowerManager actual constructor(applicationProvider: ApplicationProvider) {
    actual fun isDeviceAwake(): Boolean {
        // Desktop has no interactive/idle gate equivalent for recovery.
        return true
    }

    actual val deviceAwake: Flow<Boolean>
        get() = flowOf(true)
}
