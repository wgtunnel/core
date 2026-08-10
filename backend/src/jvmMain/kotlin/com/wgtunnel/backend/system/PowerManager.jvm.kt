package com.wgtunnel.backend.system

import com.wgtunnel.backend.ApplicationProvider

actual class PowerManager actual constructor(applicationProvider: ApplicationProvider) {
    actual fun isDeviceAwake(): Boolean {
        // TODO fix with actual power manager detection for desktop
        return true
    }
}
