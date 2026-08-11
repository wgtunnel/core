package com.wgtunnel.backend.system

import com.wgtunnel.backend.ApplicationProvider
import kotlinx.coroutines.flow.Flow

expect class PowerManager(applicationProvider: ApplicationProvider) {
    fun isDeviceAwake(): Boolean

    val deviceAwake: Flow<Boolean>
}
