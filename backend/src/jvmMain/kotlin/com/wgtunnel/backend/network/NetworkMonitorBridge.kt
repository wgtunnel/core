package com.wgtunnel.backend.network

import co.touchlab.kermit.Logger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class NetworkInfoDto(
    val type: String = "disconnected",
    val interfaceName: String = "",
    val ifIndex: UInt = 0u,
    val ssid: String = "",
    val bssid: String = "",
    val hasIpv4: Boolean = false,
    val hasIpv6: Boolean = false,
    val dnsServers: List<String> = emptyList(),
) {
    val isConnected: Boolean
        get() = type != "disconnected" && type.isNotBlank()

    val isUsable: Boolean
        get() = isConnected && (hasIpv4 || hasIpv6)

    fun snapshotKey(): String {
        return listOf(type, interfaceName, ifIndex.toString(), ssid, bssid).joinToString("|")
    }
}

object NetworkMonitorBridge {
    private val log = Logger.withTag("NetworkMonitor")
    private val json = Json { ignoreUnknownKeys = true }
    private val _info = MutableStateFlow(NetworkInfoDto())
    val info: StateFlow<NetworkInfoDto> = _info.asStateFlow()

    fun onNativeInfo(raw: String) {
        val parsed = runCatching {
            json.decodeFromString<NetworkInfoDto>(raw)
        }
            .onFailure { log.w(it) { "Failed to parse native network info: $raw" } }
            .getOrElse {
                return
            }
        if (_info.value != parsed) {
            log.d {
                "Network ${parsed.type} iface=${parsed.interfaceName} ssid=${parsed.ssid} bssid=${parsed.bssid}"
            }
        }
        _info.value = parsed
    }

    fun start(): Boolean = NetworkMonitorNative.start() >= 0

    fun stop() = NetworkMonitorNative.stop()

    fun current(): NetworkInfoDto = runCatching {
        json.decodeFromString<NetworkInfoDto>(NetworkMonitorNative.getInfoJson())
    }
        .getOrElse { NetworkInfoDto() }
}
