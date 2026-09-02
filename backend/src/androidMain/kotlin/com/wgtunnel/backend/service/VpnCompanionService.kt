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
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChangedBy
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.merge
import kotlinx.coroutines.flow.onStart
import kotlinx.coroutines.flow.take
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

    @Volatile private var userActivatedShutdown = false

    fun shutdown() {
        userActivatedShutdown = true
        stopSelf()
    }

    override fun onCreate() {
        super.onCreate()
        log.d { "CompanionService created" }
        // startForeground before publishing ready so we don't try to start the VpnService
        // before we are foregrounded
        launchForegroundNotification()
        serviceManager.set(this)
        observeVpnPersistentNotification()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        if (userActivatedShutdown) {
            stopSelf()
            return START_NOT_STICKY
        }
        launchForegroundNotification()
        serviceManager.set(this)
        val isSystemRestart =
            intent?.component == null || intent.component!!.packageName != packageName

        if (isSystemRestart) {
            // VpnService is not an FGS and will not restart after process death when sticky. This
            // companion service is the FGS
            // Android actually brings back so we will trigger the restore from here.
            log.i { "VpnCompanionService restarted by system (sticky)" }
            RuntimeManager.alwaysOnCallback?.onStickyRestart()
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
            val statusFlow =
                combine(
                        backend.status,
                        provider.persistentNotificationSignals.onStart { emit(Unit) },
                    ) { status, _ ->
                        status
                    }
                    .distinctUntilChangedBy { provider.persistentNotificationKey(it) }
            merge(statusFlow.take(1), statusFlow.drop(1).debounce(700.milliseconds)).collect {
                status ->
                val notification = provider.buildVpnPersistentNotification(status)
                notificationManager.notify(
                    provider.vpnNotificationId,
                    notification,
                )
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
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        serviceManager.clearCompanionService()
        backend.applicationProvider.refreshStatusUi()
        super.onDestroy()
    }
}
