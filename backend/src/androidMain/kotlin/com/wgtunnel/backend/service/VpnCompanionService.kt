package com.wgtunnel.backend.service

import android.app.NotificationManager
import android.content.Intent
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import co.touchlab.kermit.Logger
import com.wgtunnel.backend.AndroidApplicationProvider
import com.wgtunnel.backend.BackendRuntime
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChangedBy
import kotlinx.coroutines.launch

internal class VpnCompanionService : LifecycleService() {

    val log = Logger.withTag("VpnCompanionService")

    private val serviceManager
        get() = BackendRuntime.requireManager()

    private val backend
        get() = BackendRuntime.requireBackend()

    private val provider
        get() = BackendRuntime.requireProvider() as AndroidApplicationProvider

    private val notificationManager: NotificationManager by lazy {
        getSystemService(NOTIFICATION_SERVICE) as NotificationManager
    }

    fun shutdown() {
        stopSelf()
    }

    override fun onCreate() {
        super.onCreate()
        serviceManager.set(this)
        log.d { "CompanionService created" }
        launchForegroundNotification()
        observeVpnPersistentNotification()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        serviceManager.set(this)
        val isSystemRestart =
            intent?.component == null || intent.component!!.packageName != packageName

        if (isSystemRestart) {
            log.i { "VpnCompanionService started by system" }
            launchForegroundNotification()
        }
        return START_STICKY
    }

    private fun launchForegroundNotification() {
        ServiceCompat.startForeground(
            this,
            provider.vpnNotificationId,
            provider.vpnInitNotification,
            RuntimeManager.SPECIAL_USE_SERVICE_TYPE_ID,
        )
    }

    @OptIn(FlowPreview::class)
    private fun observeVpnPersistentNotification() {
        lifecycleScope.launch {
            backend.status
                .distinctUntilChangedBy { it.toNotificationComparisonKey() }
                .debounce(700.milliseconds)
                .collect { status ->
                    val notification = provider.buildVpnPersistentNotification(status)
                    notificationManager.notify(
                        provider.vpnNotificationId,
                        notification,
                    )
                    // refresh tile
                    backend.applicationProvider.refreshStatusUi()
                }
        }
    }

    override fun onBind(intent: Intent): IBinder? {
        super.onBind(intent)
        return null
    }

    override fun onDestroy() {
        log.d("CompanionService destroyed")
        serviceManager.clearCompanionService()
        backend.applicationProvider.refreshStatusUi()
        super.onDestroy()
    }
}
