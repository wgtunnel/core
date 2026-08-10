package com.wgtunnel.backend.system

import com.wgtunnel.backend.ApplicationProvider

expect class PowerManager(applicationProvider: ApplicationProvider) {
    fun isDeviceAwake(): Boolean
}
