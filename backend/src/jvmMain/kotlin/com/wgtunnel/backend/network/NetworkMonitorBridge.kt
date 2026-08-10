package com.wgtunnel.backend.network

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
)

internal object NetworkMonitorBridge {
    private val json = Json { ignoreUnknownKeys = true }
    private val _info = MutableStateFlow(NetworkInfoDto())
    val info: StateFlow<NetworkInfoDto> = _info.asStateFlow()

    fun onNativeInfo(raw: String) {
        _info.value = runCatching { json.decodeFromString<NetworkInfoDto>(raw) }
            .getOrElse { NetworkInfoDto() }
    }

    fun start(): Boolean = NetworkMonitorNative.start() >= 0

    fun stop() = NetworkMonitorNative.stop()

    fun current(): NetworkInfoDto =
        runCatching {
            json.decodeFromString<NetworkInfoDto>(NetworkMonitorNative.getInfoJson())
        }.getOrElse { NetworkInfoDto() }
}