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
import java.util.UUID
import kotlinx.serialization.json.Json

internal class WireGuardTunnelEngine(private val runtimeManager: RuntimeManager) : TunnelEngine {

    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    override suspend fun start(
        tunnelId: Int,
        handle: Int,
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig?,
        destroyRuntimeOnFailure: Boolean,
        outerConfig: Config?,
    ): EngineStartResult {
        val ifName = interfacePrefix() + tunnelId

        // Only the physical hop binds a host UDP port. Inner NetstackBind has none.
        val physicalListen =
            if (outerConfig != null) outerConfig.`interface`.listenPort
            else mode.config.`interface`.listenPort
        physicalListen?.let { PortUtils.waitForUdpPortAvailable(it) }
        val outerQuick = outerConfig?.asQuickString()

        val runtimeDnsConfig =
            tunnelDnsConfig
                ?: run {
                    if (mode is BackendMode.Proxy.KillSwitchPrimary) {
                        val servers =
                            mode.config.parseDnsServersOnly().map { DnsHostUtils.ensurePort53(it) }
                        if (servers.isEmpty()) {
                            throw BackendException.ConfigMissingDNS(
                                "Kill switch requires at least one DNS server in the tunnel config"
                            )
                        }
                        TunnelDnsConfig(defaultTransport = "plain", upstream = servers)
                    } else {
                        null
                    }
                }
        val dnsJson = runtimeDnsConfig?.let { json.encodeToString(it) }

        when (mode) {
            is BackendMode.Proxy.KillSwitchPrimary -> {
                val proxyConfig = buildBridgeProxyConfig()
                startProxyTunnel(
                    handle,
                    ifName,
                    mode.config,
                    proxyConfig,
                    withBridge = true,
                    runtimeDnsConfig,
                    dnsJson,
                    outerQuick,
                )
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
                    handle,
                    ifName,
                    mode.config,
                    mode.proxyConfig,
                    withBridge = false,
                    runtimeDnsConfig,
                    dnsJson,
                    outerQuick,
                )
            }
            is BackendMode.Vpn ->
                startVpnTunnel(
                    tunnelId,
                    handle,
                    ifName,
                    mode.config,
                    dnsJson,
                    destroyRuntimeOnFailure,
                    outerQuick,
                )
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
            is BackendMode.Vpn -> VpnBackend.updateTunnelPeers(handle, config.asQuickString())
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
                runtimeManager.getOrCreateVpnRuntime().stopHevSocks5Bridge()
            }
        }
    }

    private suspend fun startVpnTunnel(
        tunnelId: Int,
        handle: Int,
        ifName: String,
        config: Config,
        dnsConfigJson: String?,
        destroyRuntimeOnFailure: Boolean,
        outerQuick: String?,
    ) {
        runtimeManager.getOrCreateVpnRuntime()
        val tunFd =
            if (runtimeManager.vpnUsesOsTunFd) {
                runtimeManager.getOrCreateVpnRuntime().detachVpnTunnelFd()
                    ?: throw BackendException.Unauthorized("Failed to create tun interface")
            } else {
                -1
            }
        val rc =
            VpnBackend.turnOn(
                handle,
                ifName,
                tunFd,
                config.asQuickString(),
                dnsConfigJson,
                runtimeManager.uapiPath,
                outerQuick,
            )
        if (rc < 0) {
            if (destroyRuntimeOnFailure) {
                runCatching { runtimeManager.destroyVpnRuntime(listOf(tunnelId)) }
            }
            throw BackendException.InternalError("Internal native error with code: $rc")
        }
    }

    private suspend fun startProxyTunnel(
        handle: Int,
        ifName: String,
        config: Config,
        proxyConfig: ProxyConfig,
        withBridge: Boolean,
        runtimeDnsConfig: TunnelDnsConfig?,
        dnsConfigJson: String?,
        outerQuick: String?,
    ) {
        val quickConfig = buildProxiedQuickString(config, proxyConfig, runtimeDnsConfig)
        val rc =
            ProxyBackend.startProxy(
                handle,
                ifName,
                quickConfig,
                runtimeManager.uapiPath,
                if (withBridge) 1 else 0,
                dnsConfigJson,
                outerQuick,
            )
        if (rc < 0) {
            throw BackendException.InternalError("Internal native error")
        }
        if (withBridge) {
            try {
                val port =
                    proxyConfig.socks5?.port
                        ?: throw BackendException.InternalError("Bridge port not set")
                val pass =
                    proxyConfig.socks5.password
                        ?: throw BackendException.InternalError("Bridge pass not set")
                runtimeManager.getOrCreateVpnRuntime().startHevSocks5Bridge(port, pass)
            } catch (t: Throwable) {
                // Native start already took ownership; tear down so the caller can release cleanly.
                runCatching { ProxyBackend.turnProxyTunnelOff(handle) }
                throw t
            }
        }
    }

    private fun buildBridgeProxyConfig(): ProxyConfig =
        ProxyConfig(
            socks5 =
                ProxyConfig.Socks5(
                    port = PortUtils.getAvailableTcpPort(VpnRuntime.HEV_BRIDGE_TRAFFIC_TAG),
                    username = LOCKDOWN_USERNAME,
                    password = UUID.randomUUID().toString(),
                )
        )

    private fun buildProxiedQuickString(
        config: Config,
        proxyConfig: ProxyConfig,
        runtimeDnsConfig: TunnelDnsConfig?,
    ): String =
        buildString {
            append(configForProxyEngine(config, runtimeDnsConfig).asQuickString())
            append('\n')
            append(proxyConfig.toQuickString())
        }

    private fun configForProxyEngine(config: Config, runtimeDnsConfig: TunnelDnsConfig?): Config {
        if (runtimeDnsConfig == null) return config
        val fakeDns =
            if (config.`interface`.hasIpv6Address) {
                "${runtimeDnsConfig.fakeDns},${runtimeDnsConfig.fakeDnsV6}"
            } else {
                runtimeDnsConfig.fakeDns
            }
        return config.copy(`interface` = config.`interface`.copy(dns = fakeDns))
    }

    companion object {
        const val WGT_INTERFACE_PREFIX = "wgtun"
        const val LOCKDOWN_USERNAME = "local"

        fun interfacePrefix(): String =
            System.getProperty("wgtunnel.iface.prefix") ?: WGT_INTERFACE_PREFIX
    }
}
