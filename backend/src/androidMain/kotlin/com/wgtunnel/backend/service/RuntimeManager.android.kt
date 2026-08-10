package com.wgtunnel.backend.service

import android.content.Intent
import co.touchlab.kermit.Logger
import com.wgtunnel.backend.AndroidApplicationProvider
import com.wgtunnel.backend.ApplicationProvider
import com.wgtunnel.backend.BypassSocket
import com.wgtunnel.backend.exception.BackendException
import com.wgtunnel.backend.model.KillSwitchConfig
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull

actual class RuntimeManager actual constructor(applicationProvider: ApplicationProvider) {

    private val log = Logger.withTag("AndroidServiceManager")

    private val context = (applicationProvider as AndroidApplicationProvider).context

    actual val uapiPath: String
        get() = context.dataDir.absolutePath

    actual val vpnUsesOsTunFd: Boolean
        get() = true

    private val _vpnService = MutableStateFlow<VpnService?>(null)
    internal val vpnServiceFlow: StateFlow<VpnService?> = _vpnService.asStateFlow()

    private val _tunnelService = MutableStateFlow<TunnelService?>(null)
    internal val tunnelServiceFlow: StateFlow<TunnelService?> = _tunnelService.asStateFlow()

    private val _companionService = MutableStateFlow<VpnCompanionService?>(null)
    internal val companionServiceFlow: StateFlow<VpnCompanionService?> =
        _companionService.asStateFlow()

    internal fun set(service: VpnService) {
        _vpnService.value = service
        BypassSocket.setSocketProtector(service)
    }

    internal fun set(service: TunnelService) {
        _tunnelService.value = service
    }

    internal fun set(service: VpnCompanionService) {
        _companionService.value = service
    }

    fun clearVpnService() {
        BypassSocket.setSocketProtector(null)
        _vpnService.value = null
    }

    fun clearTunnelService() {
        _tunnelService.value = null
    }

    fun clearCompanionService() {
        _companionService.value = null
    }

    actual suspend fun getOrCreateVpnRuntime(): VpnRuntime {
        // companion is required for foreground notification
        getCompanionService()
        val vpnService = getVpnService()
        // re-apply protector in case of restart
        BypassSocket.setSocketProtector(vpnService)
        delay(JNI_PROP_DELAY_MILLIS.milliseconds)
        return vpnService
    }

    actual suspend fun getOrCreateTunnelRuntime(): TunnelRuntime {
        return getTunnelServiceInternal()
    }

    suspend fun stopVpnService() {
        val service = _vpnService.value ?: return
        // don't shut down the vpn if we have kill switch active
        if (service.isKillSwitchActive) return
        try {
            service.shutdown()
            withTimeoutOrNull(SERVICE_SHUTDOWN_TIMEOUT_MILLIS.milliseconds) {
                vpnServiceFlow.first { it == null }
            }
        } finally {
            clearVpnService()
        }
    }

    actual suspend fun destroyTunnelRuntime() {
        val service = _tunnelService.value ?: return
        try {
            service.shutdown()
            withTimeoutOrNull(SERVICE_SHUTDOWN_TIMEOUT_MILLIS.milliseconds) {
                tunnelServiceFlow.first { it == null }
            }
        } finally {
            clearTunnelService()
        }
    }

    suspend fun stopCompanionService() {
        val service = _companionService.value ?: return
        try {
            service.shutdown()
            withTimeoutOrNull(SERVICE_SHUTDOWN_TIMEOUT_MILLIS.milliseconds) {
                companionServiceFlow.first { it == null }
            }
        } finally {
            clearCompanionService()
        }
    }

    actual suspend fun destroyVpnRuntime(tunnelIds: List<Int>) {
        stopVpnService()
        stopCompanionService()
    }

    internal suspend fun getVpnService(): VpnService {
        if (android.net.VpnService.prepare(context) != null) {
            throw BackendException.Unauthorized("Permission unavailable to use VpnService")
        }
        if (_vpnService.value == null) {
            VpnService.start(context, VpnService::class.java)
        }
        return withTimeoutOrThrow(SERVICE_START_TIMEOUT_MILLIS) {
            vpnServiceFlow.filterNotNull().first()
        }
    }

    internal suspend fun getCompanionService(): VpnCompanionService {
        if (_companionService.value == null) {
            context.startForegroundService(Intent(context, VpnCompanionService::class.java))
        }
        return withTimeoutOrThrow(SERVICE_START_TIMEOUT_MILLIS) {
            companionServiceFlow.filterNotNull().first()
        }
    }

    private suspend fun getTunnelServiceInternal(): TunnelService {
        if (_tunnelService.value == null) {
            context.startForegroundService(Intent(context, TunnelService::class.java))
        }
        return withTimeoutOrThrow(SERVICE_START_TIMEOUT_MILLIS) {
            tunnelServiceFlow.filterNotNull().first()
        }
    }

    actual suspend fun setKillSwitch(config: KillSwitchConfig?) {
        val vpnService = getVpnService()
        vpnService.setKillSwitch(config)
    }

    actual suspend fun isKillSwitchEnabled(): Boolean {
        return _vpnService.value == null || getVpnService().currentKillSwitchConfig != null
    }

    private suspend inline fun <T> withTimeoutOrThrow(
        timeoutMs: Long,
        crossinline block: suspend () -> T,
    ): T {
        return try {
            withTimeout(timeoutMs.milliseconds) { block() }
        } catch (e: TimeoutCancellationException) {
            log.e(e) { "Timed out waiting for service" }
            throw BackendException.InternalError("Failed to acquire service")
        }
    }

    companion object {
        const val JNI_PROP_DELAY_MILLIS = 50L
        const val SERVICE_START_TIMEOUT_MILLIS = 3_000L
        const val SERVICE_SHUTDOWN_TIMEOUT_MILLIS = 1_500L
        const val SPECIAL_USE_SERVICE_TYPE_ID = 1 shl 30
        const val DEFAULT_MTU = 1280

        // Android-only
        var alwaysOnCallback: AlwaysOnCallback? = null
    }
}
