package com.wgtunnel.backend.service

import android.content.Context
import android.content.Intent
import android.net.TrafficStats
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import co.touchlab.kermit.Logger
import com.wgtunnel.backend.AndroidApplicationProvider
import com.wgtunnel.backend.BackendRuntime
import com.wgtunnel.backend.BypassSocket
import com.wgtunnel.backend.SocketProtector
import com.wgtunnel.backend.Tunnel
import com.wgtunnel.backend.model.KillSwitchConfig
import com.wgtunnel.backend.model.dns.TunnelDnsConfig
import com.wgtunnel.backend.service.RuntimeManager.Companion.DEFAULT_MTU
import com.wgtunnel.backend.util.NetworkUtils
import com.wgtunnel.hevtunnel.HevTunnelConfig
import com.wgtunnel.hevtunnel.TProxyService
import com.wgtunnel.parser.Config
import java.io.IOException
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

internal class VpnService : android.net.VpnService(), SocketProtector, VpnRuntime {

    private val log = Logger.withTag("VpnService")

    private val serviceManager
        get() = BackendRuntime.requireManager()

    private val backend
        get() = BackendRuntime.requireBackend()

    private val provider
        get() = BackendRuntime.requireProvider() as AndroidApplicationProvider

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val shutdownScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var hevBridgeJob: Job? = null
    @Volatile private var hevBridgeFd: ParcelFileDescriptor? = null
    @Volatile private var vpnTunFd: ParcelFileDescriptor? = null

    @Volatile internal var currentKillSwitchConfig: KillSwitchConfig? = null

    @Volatile var isKillSwitchActive = false

    override fun onCreate() {
        serviceManager.set(this)
        super.onCreate()
    }

    override fun onDestroy() {
        log.d { "VpnService destroyed" }
        try {
            BypassSocket.setSocketProtector(null)
            serviceManager.clearVpnService()
            closeVpnTunnelFd()
            disableKillSwitch()
            hevBridgeJob?.cancel()
            serviceScope.cancel()
            stopHevSocks5Bridge()
        } finally {
            super.onDestroy()
        }
    }

    override fun onRevoke() {
        log.w { "VPN revoked by user via system settings" }
        BypassSocket.setSocketProtector(null)
        disableKillSwitch()
        stopHevSocks5Bridge()
        shutdownScope.launch { backend.stopAllActiveTunnels() }
        // Stop the companion foreground service alongside the VPN teardown from revoke
        stopService(Intent(this, VpnCompanionService::class.java))
        closeVpnTunnelFd()
        stopSelf()
        super.onRevoke()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        serviceManager.set(this)

        serviceScope.launch { serviceManager.getCompanionService() }

        // system recovery restart
        if (intent == null) {
            return START_STICKY
        }

        val isUserLaunch = intent.getBooleanExtra(getUserLaunchExtraKey(this), false)

        val platformSaysAlwaysOn =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                isAlwaysOn
            } else {
                false
            }

        val isAlwaysOnTrigger =
            !isUserLaunch && (intent.action == SERVICE_INTERFACE || platformSaysAlwaysOn)

        if (isAlwaysOnTrigger) {
            log.d { "VpnService started by system (Always-On trigger)" }
            RuntimeManager.alwaysOnCallback?.alwaysOnTriggered()
        }

        return START_STICKY
    }

    fun shutdown() {
        // have to close fds before we can trigger service shutdown
        closeVpnTunnelFd()
        disableKillSwitch()
        stopSelf()
    }

    private fun startHevBridge(port: Int, pass: String): Job {
        log.d { "Starting hev-socks5-tunnel bridge..." }
        val job = serviceScope.launch {
            TrafficStats.setThreadStatsTag(VpnRuntime.HEV_BRIDGE_TRAFFIC_TAG)
            try {
                val vpnFd = hevBridgeFd ?: throw IOException("No VPN interface fd available")

                repeat(60) { attempt ->
                    try {
                        java.net.Socket().use { socket ->
                            socket.connect(java.net.InetSocketAddress(LOCALHOST, port), 800)
                        }

                        log.d {
                            "SOCKS5 proxy is ready on port $port, starting HEV bridge (attempt ${attempt + 1})"
                        }

                        val config =
                            HevTunnelConfig(
                                port = port,
                                mtu = DEFAULT_MTU,
                                ipv4 = IPV4_INTERFACE_ADDRESS,
                                ipv6 = IPV6_INTERFACE_ADDRESS,
                                address = LOCALHOST,
                                username = LOCKDOWN_USERNAME,
                                password = pass,
                            )
                        val hevConfigFile =
                            TProxyService.createHevTunnelConfig(config, this@VpnService.cacheDir)
                        TProxyService.TProxyStartService(hevConfigFile.absolutePath, vpnFd.fd)

                        log.d { "HEV bridge started successfully, exiting coroutine" }
                        return@launch // safe to exit as hev handles own threading internally
                    } catch (e: Exception) {
                        log.w(e) { "SOCKS5 connect failed (attempt ${attempt + 1})" }
                        if (attempt % 5 == 0) {
                            log.d { "SOCKS5 not ready yet, retrying..." }
                        }
                        delay(300.milliseconds)
                    }
                }
                log.e { "Timed out waiting for SOCKS5 proxy to be ready" }
            } catch (e: Exception) {
                log.e(e) { "Failed to start HEV bridge" }
            } finally {
                TrafficStats.clearThreadStatsTag()
            }
        }

        // stop HEV when the job is canceled from stopHevSocks5Bridge or onDestroy
        job.invokeOnCompletion { cause ->
            if (cause != null) { // canceled or failed
                log.d { "HEV bridge job stopped, shutting down native HEV" }
                TProxyService.TProxyStopService()
            }
            hevBridgeJob = null
        }

        return job
    }

    private fun disableKillSwitch() {
        hevBridgeFd?.close()
        hevBridgeFd = null
        currentKillSwitchConfig = null
    }

    fun setKillSwitch(config: KillSwitchConfig?) {
        if (config == null) return disableKillSwitch()

        if (hevBridgeFd != null && currentKillSwitchConfig == config) {
            log.d { "Kill Switch already active with identical config, skipping" }
            return
        }

        hevBridgeFd?.close()
        val intent = provider.createVpnConfigurePendingIntent(this@VpnService)
        hevBridgeFd =
            Builder()
                .apply {
                    setSession(LOCKDOWN_SESSION_NAME)
                    setConfigureIntent(intent)
                    addAddress(IPV4_INTERFACE_ADDRESS, 32)
                    if (config.dualStack) addAddress(IPV6_INTERFACE_ADDRESS, 128)
                    if (config.allowedIps.isEmpty()) {
                        addRoute(IPV4_DEFAULT_ROUTE, 0)
                    } else {
                        config.allowedIps.forEach { net ->
                            log.d { "Adding allowedIp to kill switch: $net" }
                            val (address, prefix) = NetworkUtils.parseInetNetwork(net)
                            addRoute(address, prefix)
                        }
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        setMetered(config.metered)
                    }
                    addRoute(IPV6_DEFAULT_ROUTE, 0)
                    setMtu(DEFAULT_MTU)
                    addDnsServer(TunnelDnsConfig.FAKE_DNS_V4)
                    if (config.dualStack) addDnsServer(TunnelDnsConfig.FAKE_DNS_V6)
                }
                .establish()
        isKillSwitchActive = true
        currentKillSwitchConfig = config
    }

    override suspend fun createTunInterface(tunnel: Tunnel, config: Config, fakeDns: Boolean) {
        val intent = provider.createVpnConfigurePendingIntent(this)
        vpnTunFd?.close()
        vpnTunFd = null
        vpnTunFd =
            Builder()
                .apply {
                    setSession(tunnel.name)
                    setConfigureIntent(intent)
                    setMtu(config.`interface`.mtu ?: DEFAULT_MTU)
                    setBlocking(true)
                    setUnderlyingNetworks(null)

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        setMetered(tunnel.isMetered)
                    }

                    config.`interface`.includedApplications?.forEach { addAllowedApplication(it) }
                    config.`interface`.excludedApplications?.forEach {
                        addDisallowedApplication(it)
                    }

                    var hasIpv4 = false
                    var hasIpv6 = false
                    var sawDefaultRoute = false

                    config.`interface`.address
                        ?.split(",")
                        ?.map { it.trim() }
                        ?.filter { it.isNotEmpty() }
                        ?.forEach { rawAddress ->
                            val net = NetworkUtils.parseInetNetwork(rawAddress)
                            addAddress(net.hostAddress, net.prefixLength)
                            if (net.isIpv4) hasIpv4 = true else hasIpv6 = true
                        }

                    // Parse peer routes
                    config.peers.forEach { peer ->
                        peer.allowedIPs
                            ?.split(",")
                            ?.map { it.trim() }
                            ?.filter { it.isNotEmpty() }
                            ?.forEach { entry ->
                                val net = NetworkUtils.parseInetNetwork(entry)
                                addRoute(net.hostAddress, net.prefixLength)
                                if (net.prefixLength == 0) sawDefaultRoute = true
                                if (net.isIpv4) hasIpv4 = true else hasIpv6 = true
                            }
                    }

                    // "Kill-switch" semantics (mirrors wireguard-android)
                    val isKillSwitchRouting = sawDefaultRoute && config.peers.size == 1

                    if (!isKillSwitchRouting) {
                        allowFamily(OsConstants.AF_INET)
                        allowFamily(OsConstants.AF_INET6)
                    }

                    if (fakeDns) {
                        if (hasIpv4) addDnsServer(TunnelDnsConfig.FAKE_DNS_V4)
                        if (hasIpv6) addDnsServer(TunnelDnsConfig.FAKE_DNS_V6)
                    }

                    // Only add DNS servers whose family is supported
                    config.`interface`.dns?.let { rawDns ->
                        val dnsConfig = NetworkUtils.parseDns(rawDns)
                        if (!fakeDns)
                            dnsConfig.dnsServers.forEach { dnsServer ->
                                val isIpv6 = ':' in dnsServer
                                if ((isIpv6 && hasIpv6) || (!isIpv6 && hasIpv4)) {
                                    addDnsServer(dnsServer)
                                } else {
                                    log.w {
                                        "Dropped DNS server $dnsServer: IP family not allowed by interface/routes"
                                    }
                                }
                            }
                        dnsConfig.searchDomains.forEach { addSearchDomain(it) }
                    }
                }
                .establish()
    }

    override fun detachVpnTunnelFd(): Int? {
        return vpnTunFd?.dup()?.detachFd()
    }

    fun closeVpnTunnelFd() {
        try {
            vpnTunFd?.close()
        } catch (e: Exception) {
            log.e(throwable = e) { "Failed to close VPN fd" }
        }
        vpnTunFd = null
    }

    override fun startHevSocks5Bridge(port: Int, pass: String) {
        if (hevBridgeJob != null) return
        hevBridgeJob = startHevBridge(port, pass)
    }

    override fun stopHevSocks5Bridge() {
        hevBridgeJob?.cancel()
        hevBridgeJob = null

        try {
            TProxyService.TProxyStopService()
        } catch (e: Exception) {
            log.w(e) { "TProxyStopService failed, may already be stopped" }
        }
    }

    override fun bypass(fd: Int): Int {
        return try {
            if (protect(fd)) 1 else 0
        } catch (e: Exception) {
            log.e(e) { "Failed to protect/bypass fd=$fd" }
            0
        }
    }

    companion object {

        private fun getUserLaunchExtraKey(context: Context): String {
            return "${context.packageName}.EXTRA_IS_USER_LAUNCH"
        }

        @JvmStatic
        fun start(context: Context, serviceClass: Class<out VpnService>) {
            val intent =
                Intent(context, serviceClass).apply {
                    action = SERVICE_INTERFACE
                    putExtra(getUserLaunchExtraKey(context), true)
                }
            context.startService(intent)
        }

        private const val LOCKDOWN_SESSION_NAME = "Lockdown"
        private const val LOCALHOST = "127.0.0.1"
        private const val IPV4_INTERFACE_ADDRESS = "10.0.0.1"
        private const val IPV6_INTERFACE_ADDRESS = "2001:db8::1"
        const val LOCKDOWN_USERNAME = "local"
        private const val IPV4_DEFAULT_ROUTE = "0.0.0.0"
        private const val IPV6_DEFAULT_ROUTE = "::"
    }
}
