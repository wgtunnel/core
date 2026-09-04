package com.wgtunnel.backend.system

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.loadBackendNativeLibrary
import com.wgtunnel.backend.network.NetworkInfoDto
import com.wgtunnel.backend.network.NetworkMonitorBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.serialization.json.Json

class DesktopNativeNetworkMonitor(
    scope: CoroutineScope,
    startNative: Boolean = true,
) : NetworkMonitor {
    private val log = Logger.withTag("DesktopNativeNetworkMonitor")
    private val json = Json { ignoreUnknownKeys = true }

    val info: StateFlow<NetworkInfoDto> = NetworkMonitorBridge.info

    init {
        if (startNative) {
            loadBackendNativeLibrary()
            val ok = NetworkMonitorBridge.start()
            if (!ok) {
                log.e { "Failed to start native network monitor" }
            } else {
                runCatching {
                    val current = NetworkMonitorBridge.current()
                    NetworkMonitorBridge.onNativeInfo(
                        json.encodeToString(NetworkInfoDto.serializer(), current)
                    )
                }
                    .onFailure { log.w(it) { "Failed to seed network monitor snapshot" } }
                log.i {
                    "Native network monitor started type=${info.value.type} iface=${info.value.interfaceName}"
                }
            }
        }
    }

    override val networkState: StateFlow<NetworkSnapshot?> =
        info
            .map { snapshot ->
                NetworkSnapshot(
                    key = snapshot.snapshotKey(),
                    hasIpv6 = snapshot.hasIpv6,
                    isUsable = snapshot.isUsable,
                )
            }
            .stateIn(
                scope = scope,
                started = SharingStarted.Eagerly,
                initialValue =
                    NetworkSnapshot(
                        key = "desktop-initial",
                        hasIpv6 = false,
                        isUsable = false,
                    ),
            )

    fun stop() {
        runCatching { NetworkMonitorBridge.stop() }
            .onFailure { log.w(it) { "Failed to stop native network monitor" } }
    }
}
