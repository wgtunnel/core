package com.wgtunnel.backend

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import com.wgtunnel.backend.state.BackendStatus

interface AndroidApplicationProvider : ApplicationProvider {
    val context: Context
    val vpnNotificationId: Int
    val proxyNotificationId: Int

    val vpnInitNotification: Notification
    val proxyInitNotification: Notification

    fun createVpnConfigurePendingIntent(context: Context): PendingIntent

    suspend fun buildVpnPersistentNotification(status: BackendStatus): Notification

    suspend fun buildProxyPersistentNotification(status: BackendStatus): Notification
}
