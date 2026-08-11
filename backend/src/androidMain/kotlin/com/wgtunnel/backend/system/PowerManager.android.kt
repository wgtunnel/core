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

    actual fun isDeviceAwake(): Boolean {
        // screen on / device interactive
        if (!powerManager.isInteractive) return false
        // deep idle
        if (powerManager.isDeviceIdleMode) return false
        return true
    }

    actual val deviceAwake: Flow<Boolean> = callbackFlow {
        // Init state
        trySend(powerManager.isInteractive)

        val receiver =
            object : BroadcastReceiver() {
                override fun onReceive(context: Context?, intent: Intent?) {
                    // Re-query instead of trusting the action string
                    trySend(powerManager.isInteractive)
                }
            }

        val filter =
            IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_ON)
                addAction(Intent.ACTION_SCREEN_OFF)
            }

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
