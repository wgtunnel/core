package com.wgtunnel.backend.system

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.PowerManager as AndroidPowerManager
import androidx.core.content.getSystemService
import com.wgtunnel.backend.AndroidApplicationProvider
import com.wgtunnel.backend.ApplicationProvider
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged

actual class PowerManager actual constructor(applicationProvider: ApplicationProvider) {

    private val context = (applicationProvider as AndroidApplicationProvider).context

    private val powerManager: AndroidPowerManager =
        context.getSystemService(Context.POWER_SERVICE) as AndroidPowerManager

    /** Whether the device is free enough for full tunnel bounce (only when not in doze mode) */
    actual fun isDeviceAwake(): Boolean = !powerManager.isDeviceIdleMode

    actual val deviceAwake: Flow<Boolean> = callbackFlow {
        trySend(isDeviceAwake())

        val receiver =
            object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    trySend(isDeviceAwake())
                }
            }

        val filter =
            IntentFilter().apply { addAction(AndroidPowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED) }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag") context.registerReceiver(receiver, filter)
        }

        awaitClose {
            try {
                context.unregisterReceiver(receiver)
            } catch (_: IllegalArgumentException) {
                // already unregistered
            }
        }
    }
        .distinctUntilChanged()
}
