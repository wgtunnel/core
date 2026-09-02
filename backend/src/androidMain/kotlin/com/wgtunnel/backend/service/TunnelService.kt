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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChangedBy
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.merge
import kotlinx.coroutines.flow.onStart
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.launch

internal class TunnelService : LifecycleService(), TunnelRuntime {

    val log = Logger.withTag("TunnelService")

    private val serviceManager
        get() = BackendRuntime.requireManager()

    private val backend
        get() = BackendRuntime.requireBackend()

    private val provider
        get() = BackendRuntime.requireProvider() as AndroidApplicationProvider

    private val shutdownScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val notificationManager: NotificationManager by lazy {
        getSystemService(NOTIFICATION_SERVICE) as NotificationManager
    }

    @Volatile private var userActivatedShutdown = false

    override fun onCreate() {
        super.onCreate()
        launchForegroundNotification()
        serviceManager.set(this)
        observeProxyPersistentNotification()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        launchForegroundNotification()
        serviceManager.set(this)

        if (intent == null) {
            log.d { "TunnelService restarted by system (sticky)" }
            RuntimeManager.alwaysOnCallback?.onStickyRestart()
        } else if (intent.component == null || intent.component!!.packageName != packageName) {
            log.d { "TunnelService started by system (Always-On trigger)" }
            RuntimeManager.alwaysOnCallback?.alwaysOnTriggered()
        }

        return START_STICKY
    }

    @OptIn(FlowPreview::class)
    private fun observeProxyPersistentNotification() {
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
                val notification = provider.buildProxyPersistentNotification(status)
                notificationManager.notify(
                    provider.proxyNotificationId,
                    notification,
                )
                backend.applicationProvider.refreshStatusUi()
            }
        }
    }

    override suspend fun shutdown() {
        userActivatedShutdown = true
        stopSelf()
    }

    override fun onDestroy() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        serviceManager.clearTunnelService()
        if (!userActivatedShutdown) {
            log.d { "Service being killed by system, clean up tunnels" }
            shutdownScope.launch {
                // TODO eventually, this should only shut down proxy mode tunnels with future multi
                // tunnel
                backend.stopAllActiveTunnels()
            }
        }
        backend.applicationProvider.refreshStatusUi()
        super.onDestroy()
    }

    override fun onBind(intent: Intent): IBinder? {
        super.onBind(intent)
        return null
    }

    fun launchForegroundNotification() {
        ServiceCompat.startForeground(
            this,
            provider.proxyNotificationId,
            provider.proxyInitNotification,
            RuntimeManager.SPECIAL_USE_SERVICE_TYPE_ID,
        )
    }
}
