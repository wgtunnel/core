package com.wgtunnel.backend

import com.wgtunnel.backend.exception.BackendException
import com.wgtunnel.backend.model.BackendMode
import com.wgtunnel.backend.model.EngineStartResult
import com.wgtunnel.backend.model.ProxyConfig
import com.wgtunnel.backend.model.dns.TunnelDnsConfig
import com.wgtunnel.backend.service.RuntimeManager
import com.wgtunnel.backend.service.VpnRuntime
import com.wgtunnel.backend.util.DnsHostUtils
import com.wgtunnel.backend.util.PortUtils
import com.wgtunnel.backend.util.parseDnsServersOnly
import com.wgtunnel.parser.ActiveConfig
import com.wgtunnel.parser.Config
import com.wgtunnel.parser.PeerSection
import kotlinx.serialization.json.Json
import java.util.UUID

internal class WireGuardTunnelEngine(
    private val runtimeManager: RuntimeManager,
) : TunnelEngine {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    override suspend fun start(
        tunnelId: Int,
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig?,
    ): EngineStartResult {
        val ifName = WGT_INTERFACE_PREFIX + tunnelId

        mode.config.`interface`.listenPort?.let { PortUtils.waitForUdpPortAvailable(it) }

        val runtimeDnsConfig =
            tunnelDnsConfig
                ?: run {
                    if (mode is BackendMode.Proxy.KillSwitchPrimary) {
                        val servers =
                            mode.config.parseDnsServersOnly().map { DnsHostUtils.ensurePort53(it) }
                        if (servers.isEmpty()) {
                            throw BackendException.ConfigMissingDNS(
                                "Kill switch requires at least one DNS server in the tunnel config",
                            )
                        }
                        TunnelDnsConfig(defaultTransport = "plain", upstream = servers)
                    } else {
                        null
                    }
                }
        val dnsJson = runtimeDnsConfig?.let { json.encodeToString(TunnelDnsConfig.serializer(), it) }

        val handle =
            when (mode) {
                is BackendMode.Proxy.KillSwitchPrimary -> {
                    val proxyConfig = buildBridgeProxyConfig()
                    startProxyTunnel(ifName, mode.config, proxyConfig, withBridge = true, dnsJson)
                }
                is BackendMode.Proxy.Standard -> {
                    mode.proxyConfig.socks5?.port?.let { port ->
                        if (!PortUtils.isTcpPortAvailable(port)) {
                            throw BackendException.Socks5PortUnavailable(
                                "SOCKS5 port $port is already in use.",
                                port,
                            )
                        }
                    }
                    mode.proxyConfig.http?.port?.let { port ->
                        if (!PortUtils.isTcpPortAvailable(port)) {
                            throw BackendException.HttpPortUnavailable(
                                "HTTP listener port $port is already in use.",
                                port,
                            )
                        }
                    }
                    startProxyTunnel(
                        ifName,
                        mode.config,
                        mode.proxyConfig,
                        withBridge = false,
                        dnsJson,
                    )
                }
                is BackendMode.Vpn -> startVpnTunnel(ifName, mode.config, dnsJson)
            }

        if (handle < 0) {
            throw BackendException.InternalError("Native start failed: $handle")
        }

        return EngineStartResult(
            tunnelId = tunnelId,
            handle = handle,
            interfaceName = ifName,
            mode = mode,
        )
    }

    override suspend fun updatePeers(handle: Int, mode: BackendMode, peers: List<PeerSection>) {
        val config = mode.config.copy(peers = peers)
        when (mode) {
            is BackendMode.Proxy ->
                ProxyBackend.updateProxyTunnelPeers(handle, config.asQuickString())
            is BackendMode.Vpn ->
                VpnBackend.updateTunnelPeers(handle, config.asQuickString())
        }
    }

    override suspend fun getActiveConfig(handle: Int, mode: BackendMode): ActiveConfig? {
        val raw =
            when (mode) {
                is BackendMode.Proxy -> ProxyBackend.getProxyConfig(handle)
                is BackendMode.Vpn -> VpnBackend.getConfig(handle)
            }
        return raw?.let { ActiveConfig.parseFromIpc(it) }
    }

    override suspend fun stop(handle: Int, mode: BackendMode) {
        when (mode) {
            is BackendMode.Proxy.Standard -> ProxyBackend.turnProxyTunnelOff(handle)
            is BackendMode.Vpn -> VpnBackend.turnOff(handle)
            is BackendMode.Proxy.KillSwitchPrimary -> {
                ProxyBackend.turnProxyTunnelOff(handle)
                runtimeManager.ensureVpnReady().stopHevSocks5Bridge()
            }
        }
    }

    private suspend fun startVpnTunnel(
        ifName: String,
        config: Config,
        dnsConfigJson: String?,
    ): Int {
        val vpn = runtimeManager.ensureVpnReady()
        return if (runtimeManager.vpnUsesOsTunFd) {
            val fd =
                runtimeManager.ensureVpnReady().detachVpnTunnelFd()
                    ?: throw BackendException.Unauthorized("Failed to create tun interface")
            val handle =
                VpnBackend.turnOn(
                    ifName,
                    fd,
                    config.asQuickString(),
                    dnsConfigJson,
                    runtimeManager.uapiPath
                )
            if (handle < 0) {
                throw BackendException.InternalError("Internal native error with code: $handle")
            }
            handle
        } else {
            val handle =
                VpnBackend.turnOn(
                    ifName,
                    -1, // no-op for desktop
                    config.asQuickString(),
                    dnsConfigJson,
                    runtimeManager.uapiPath
                )
            if (handle < 0) {
                throw BackendException.InternalError("Internal native error with code: $handle")
            }
            handle
        }
    }

    private suspend fun startProxyTunnel(
        ifName: String,
        config: Config,
        proxyConfig: ProxyConfig,
        withBridge: Boolean,
        dnsConfigJson: String?,
    ): Int {
        val quickConfig = buildProxiedQuickString(config, proxyConfig)
        val handle =
            ProxyBackend.startProxy(
                ifName,
                quickConfig,
                runtimeManager.uapiPath,
                if (withBridge) 1 else 0,
                dnsConfigJson,
            )
        if (handle < 0) {
            throw BackendException.InternalError("Internal native error")
        }
        if (withBridge) {
            val port =
                proxyConfig.socks5?.port
                    ?: throw BackendException.InternalError("Bridge port not set")
            val pass =
                proxyConfig.socks5.password
                    ?: throw BackendException.InternalError("Bridge pass not set")
            runtimeManager.ensureVpnReady().startHevSocks5Bridge(port, pass)
        }
        return handle
    }

    private fun buildBridgeProxyConfig(): ProxyConfig =
        ProxyConfig(
            socks5 =
                ProxyConfig.Socks5(
                    port = PortUtils.getAvailableTcpPort(VpnRuntime.HEV_BRIDGE_TRAFFIC_TAG),
                    username = LOCKDOWN_USERNAME,
                    password = UUID.randomUUID().toString(),
                ),
        )

    private fun buildProxiedQuickString(config: Config, proxyConfig: ProxyConfig): String =
        buildString {
            append(config.asQuickString())
            append('\n')
            append(proxyConfig.toQuickString())
        }

    companion object {
        const val WGT_INTERFACE_PREFIX = "wgtun"
        const val LOCKDOWN_USERNAME = "local"
    }
}