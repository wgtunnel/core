package com.wgtunnel.backend.system

import android.os.PowerManager
import androidx.core.content.getSystemService
import com.wgtunnel.backend.AndroidApplicationProvider
import com.wgtunnel.backend.ApplicationProvider

actual class PowerManager actual constructor(applicationProvider: ApplicationProvider) {

    private val context = (applicationProvider as AndroidApplicationProvider).context

    actual fun isDeviceAwake(): Boolean {
        val pm = context.getSystemService<PowerManager>() ?: return true
        // screen on / device interactive
        if (!pm.isInteractive) return false
        // deep idle
        if (pm.isDeviceIdleMode) return false
        return true
    }
}
