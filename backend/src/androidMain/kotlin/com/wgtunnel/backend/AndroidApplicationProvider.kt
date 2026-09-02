package com.wgtunnel.backend

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import com.wgtunnel.backend.state.BackendStatus
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow

interface AndroidApplicationProvider : ApplicationProvider {
    val context: Context
    val vpnNotificationId: Int
    val proxyNotificationId: Int

    val vpnInitNotification: Notification
    val proxyInitNotification: Notification

    fun createVpnConfigurePendingIntent(context: Context): PendingIntent

    suspend fun buildVpnPersistentNotification(status: BackendStatus): Notification

    suspend fun buildProxyPersistentNotification(status: BackendStatus): Notification

    /** Comparison key for when the persistent FGS notification should be rebuilt. */
    fun persistentNotificationKey(status: BackendStatus): Any = status.toNotificationComparisonKey()

    /**
     * Signals that should rebuild the persistent notification while the companion/tunnel service is
     * alive.
     */
    val persistentNotificationSignals: Flow<Unit>
        get() = emptyFlow()
}
