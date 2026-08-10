package com.wgtunnel.backend.system

actual class PowerManager {
    actual fun isDeviceAwake(): Boolean {
        // TODO fix with actual power manager detection for desktop
        return true
    }
}