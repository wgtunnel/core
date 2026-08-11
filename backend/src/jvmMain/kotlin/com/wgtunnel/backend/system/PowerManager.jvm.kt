package com.wgtunnel.backend.system

import com.wgtunnel.backend.ApplicationProvider
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

actual class PowerManager actual constructor(applicationProvider: ApplicationProvider) {
    actual fun isDeviceAwake(): Boolean {
        // TODO fix with actual power manager detection for desktop
        return true
    }

    // TODO
    actual val deviceAwake: Flow<Boolean>
        get() = flow {}
}
