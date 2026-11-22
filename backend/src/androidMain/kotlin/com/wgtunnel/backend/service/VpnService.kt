package com.wgtunnel.backend.service

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.TrafficStats
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.OsConstants
import co.touchlab.kermit.Logger
import com.wgtunnel.backend.AndroidApplicationProvider
import com.wgtunnel.backend.BackendRuntime
import com.wgtunnel.backend.BypassSocket
import com.wgtunnel.backend.SocketProtector
import com.wgtunnel.backend.StrictSplitBridge
import com.wgtunnel.backend.Tunnel
import com.wgtunnel.backend.dns.UnderlayDnsBridge
import com.wgtunnel.backend.model.KillSwitchConfig
import com.wgtunnel.backend.model.dns.TunnelDnsConfig
import com.wgtunnel.backend.service.RuntimeManager.Companion.DEFAULT_MTU
import com.wgtunnel.backend.util.NetworkUtils
import com.wgtunnel.hevtunnel.HevTunnelConfig
import com.wgtunnel.hevtunnel.TProxyService
import com.wgtunnel.parser.Config
import java.io.IOException
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

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
    @Volatile private var hevBridgeTarget: HevBridgeTarget? = null
    @Volatile private var vpnTunFd: ParcelFileDescriptor? = null
    @Volatile private var ourVpnNetwork: Network? = null
    // The network invalidated by the most recent beginVpnNetworkAttempt()
    @Volatile private var staleVpnNetwork: Network? = null
    private var vpnNetworkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var vpnNetworkDeferred: CompletableDeferred<Network>? = null
    @Volatile private var vpnAttemptGeneration = 0
    private var vpnNetworkPollJob: Job? = null
    @Volatile private var loggedHandleFailure = false

    @Volatile internal var currentKillSwitchConfig: KillSwitchConfig? = null

    @Volatile var isKillSwitchActive = false

    internal val hasVpnTunnel: Boolean
        get() = vpnTunFd != null

    @Volatile private var userActivatedShutdown = false

    override fun onCreate() {
        StrictSplitBridge.attach(this)
        serviceManager.set(this)
        ensureVpnNetworkCallback()
        super.onCreate()
    }

    override fun onDestroy() {
        log.d { "VpnService destroyed" }
        try {
            StrictSplitBridge.clear()
            BypassSocket.setSocketProtector(null)
            serviceManager.clearVpnService()
            closeVpnTunnelFd()
            disableKillSwitch()
            hevBridgeJob?.cancel()
            serviceScope.cancel()
            stopHevSocks5Bridge()
            unregisterVpnNetworkCallback()
        } finally {
            super.onDestroy()
        }
    }

    override fun onRevoke() {
        log.w { "VPN revoked by user via system settings" }
        RuntimeManager.alwaysOnCallback?.onVpnRevoked()
        BypassSocket.setSocketProtector(null)
        disableKillSwitch()
        stopHevSocks5Bridge()
        shutdownScope.launch { backend.stopAllActiveTunnels() }
        // Stop the companion foreground service alongside the VPN teardown from revoke
        stopService(Intent(this, VpnCompanionService::class.java))
        closeVpnTunnelFd()
        unregisterVpnNetworkCallback()
        stopSelf()
        super.onRevoke()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (userActivatedShutdown) {
            // A start that lands before this instance is destroyed reaches it, not a new one.
            // Ignoring it left the service started but never registered, so every later start
            // timed out until the process died.
            if (intent == null) return START_NOT_STICKY
            log.d { "VpnService started again after shutdown, reviving" }
            userActivatedShutdown = false
        }
        serviceManager.set(this)

        serviceScope.launch { serviceManager.getCompanionService() }

        // Process death restore is owned by VpnCompanionService (the FGS)
        if (intent == null) {
            return START_NOT_STICKY
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

        return START_NOT_STICKY
    }

    fun shutdown() {
        userActivatedShutdown = true
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
                // Catches Throwable, not just Exception as a damaged/stale split install can
                // throw UnsatisfiedLinkError on first touch of TProxyService, and
                // that must never crash teardown.
                try {
                    TProxyService.TProxyStopService()
                } catch (e: Throwable) {
                    log.w(e) { "TProxyStopService failed, may already be stopped" }
                }
            }
            hevBridgeJob = null
        }

        return job
    }

    private fun disableKillSwitch() {
        stopHevSocks5Bridge()
        hevBridgeFd?.close()
        hevBridgeFd = null
        currentKillSwitchConfig = null
        isKillSwitchActive = false
        if (vpnTunFd == null) {
            stopVpnNetworkPoll()
            ourVpnNetwork = null
            UnderlayDnsBridge.setVpnNetwork(null)
        }
    }

    suspend fun setKillSwitch(config: KillSwitchConfig?) {
        if (config == null) return disableKillSwitch()

        if (hevBridgeFd != null && currentKillSwitchConfig == config) {
            log.d { "Kill Switch already active with identical config, skipping" }
            return
        }

        val intent = provider.createVpnConfigurePendingIntent(this@VpnService)
        ensureVpnNetworkCallback()
        beginVpnNetworkAttempt()
        // Establish the replacement TUN first so a failed rebuild leaves the
        // existing session and hev intact. Android replaces the VPN session
        // on a successful establish, which invalidates the old fd.
        val newFd =
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
                .establish() ?: throw IOException("Failed to establish kill switch TUN")

        awaitOurVpnNetwork()

        log.d {
            "Kill switch TUN replaced (dualStack=${config.dualStack}, metered=${config.metered}, " +
                "allowedIps=${config.allowedIps.size}); rebinding HEV to the new fd"
        }
        val oldFd = hevBridgeFd
        // HEV is bound to the previous VpnService fd. Stop the native bridge
        // so we can attach it to the new fd
        stopHevNative()
        oldFd?.close()
        hevBridgeFd = newFd
        isKillSwitchActive = true
        currentKillSwitchConfig = config
        rebindHevSocks5Bridge()
    }

    override suspend fun createTunInterface(tunnel: Tunnel, config: Config, fakeDns: Boolean) {
        ensureVpnNetworkCallback()
        beginVpnNetworkAttempt()
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

                    // Always add routes for fakeDNS to support split tunnels
                    if (fakeDns) {
                        if (hasIpv4) {
                            addDnsServer(TunnelDnsConfig.FAKE_DNS_V4)
                            addRoute(TunnelDnsConfig.FAKE_DNS_V4, 32)
                        }
                        if (hasIpv6) {
                            addDnsServer(TunnelDnsConfig.FAKE_DNS_V6)
                            addRoute(TunnelDnsConfig.FAKE_DNS_V6, 128)
                        }
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
        awaitOurVpnNetwork()
    }

    // The VPN Network (for getNetworkHandle()) is published async, and a split-tunnel VPN is never
    // the default network. The request below only requires TRANSPORT_VPN. On Android 12+ it also
    // includes networks
    // that do not apply to this UID. Below that there is no public API for the UID scope, so
    // allNetworks is polled instead. Those OEMs also drop the callback.
    // onAvailable soft-checks owner UID (see isLikelyOurs) to avoid binding to a different
    // VPN, and skips staleVpnNetwork from beginVpnNetworkAttempt.
    @Synchronized
    private fun ensureVpnNetworkCallback() {
        if (vpnNetworkCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val cb =
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    considerVpnNetwork(network, "callback")
                }

                override fun onCapabilitiesChanged(
                    network: Network,
                    networkCapabilities: NetworkCapabilities,
                ) {
                    considerVpnNetwork(network, "callback")
                }

                override fun onLost(network: Network) {
                    synchronized(this@VpnService) {
                        if (vpnNetworkCallback !== this) return
                        if (ourVpnNetwork != network) return
                        ourVpnNetwork = null
                        UnderlayDnsBridge.setVpnNetwork(null)
                        log.d { "VPN network lost" }
                    }
                }
            }
        val handler = Handler(Looper.getMainLooper())
        try {
            cm.registerNetworkCallback(vpnNetworkRequest(), cb, handler)
        } catch (e: SecurityException) {
            // setIncludeOtherUidNetworks is rejected on some builds. The allNetworks poll
            // still covers a split tunnel the narrower request cannot see.
            log.w(e) { "VPN network callback rejected; retrying without other UID networks" }
            cm.registerNetworkCallback(
                NetworkRequest.Builder()
                    .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                    .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build(),
                cb,
                handler,
            )
        }
        vpnNetworkCallback = cb
    }

    // Only TRANSPORT_VPN is required. Default capabilities hide a split tunnel that is not
    // INTERNET, TRUSTED, or NOT_RESTRICTED. clearCapabilities() is public on Android 12+.
    // Older releases only expose removeCapability for the defaults Builder() installs.
    private fun vpnNetworkRequest(): NetworkRequest {
        val builder = NetworkRequest.Builder()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.clearCapabilities()
            builder.addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            runCatching { builder.setIncludeOtherUidNetworks(true) }
                .onFailure { e -> log.w(e) { "VPN request cannot include other UID networks" } }
        } else {
            builder
                .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)
        }
        return builder.build()
    }

    private fun considerVpnNetwork(network: Network, source: String) {
        synchronized(this) {
            if (vpnNetworkCallback == null) return
            if (network == staleVpnNetwork) return
            if (!isLikelyOurs(network)) return
            val handle = vpnNetworkHandle(network)
            if (handle == 0L) return
            if (ourVpnNetwork == network) return
            applyVpnNetwork(network, handle, source)
            val pending = vpnNetworkDeferred
            if (pending != null && !pending.isCompleted) pending.complete(network)
        }
    }

    private fun isLikelyOurs(network: Network): Boolean {
        // getOwnerUid() is API 30+ so older devices accept any TRANSPORT_VPN.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return true
        val cm = getSystemService(ConnectivityManager::class.java) ?: return true
        val ownerUid = cm.getNetworkCapabilities(network)?.ownerUid ?: return true
        // <=0 is redacted/unavailable on many OEMs/API levels, not a confirmed foreign owner.
        if (ownerUid <= 0) return true
        return ownerUid == Process.myUid()
    }

    // Skip the network beginVpnNetworkAttempt just invalidated. A reconnect can briefly list
    // both the old and new VPN here, and nothing else distinguishes them.
    @Suppress("DEPRECATION")
    private fun findOurVpnNetwork(): Network? {
        val cm = getSystemService(ConnectivityManager::class.java) ?: return null
        return cm.allNetworks.firstOrNull { network ->
            if (network == staleVpnNetwork) return@firstOrNull false
            val caps = cm.getNetworkCapabilities(network) ?: return@firstOrNull false
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                isLikelyOurs(network) &&
                vpnNetworkHandle(network) != 0L
        }
    }

    private fun vpnNetworkHandle(network: Network): Long {
        return try {
            network.networkHandle
        } catch (e: Throwable) {
            if (!loggedHandleFailure) {
                loggedHandleFailure = true
                log.w(e) { "getNetworkHandle failed" }
            }
            0L
        }
    }

    @Synchronized
    private fun unregisterVpnNetworkCallback() {
        stopVpnNetworkPoll()
        vpnNetworkCallback?.let { cb ->
            try {
                getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(cb)
            } catch (_: Exception) {}
        }
        vpnNetworkCallback = null
        ourVpnNetwork = null
        staleVpnNetwork = null
        UnderlayDnsBridge.setVpnNetwork(null)
    }

    private fun applyVpnNetwork(network: Network, handle: Long, source: String) {
        ourVpnNetwork = network
        UnderlayDnsBridge.setVpnNetwork(network)
        log.d { "VPN network handle=$handle ($source)" }
    }

    // Call before a new establish() (fresh tunnel, switch, or KS TUN replace). Clears the handle
    // and remembers it as staleVpnNetwork so a late event for the old network can't complete
    // this attempt's deferred.
    @Synchronized
    private fun beginVpnNetworkAttempt() {
        stopVpnNetworkPoll()
        vpnAttemptGeneration++
        loggedHandleFailure = false
        staleVpnNetwork = ourVpnNetwork
        ourVpnNetwork = null
        UnderlayDnsBridge.setVpnNetwork(null)
        vpnNetworkDeferred = CompletableDeferred()
    }

    private suspend fun awaitOurVpnNetwork() {
        val pending = vpnNetworkDeferred ?: return
        val generation = vpnAttemptGeneration
        startVpnNetworkPoll(generation)
        val network = withTimeoutOrNull(3.seconds) { pending.await() }
        if (network == null) {
            log.w { "VPN network not published within 3s; DNS stays black-holed until it is" }
        }
    }

    private fun startVpnNetworkPoll(generation: Int) {
        val job = serviceScope.launch {
            var elapsed = 0
            while (isActive && generation == vpnAttemptGeneration && ourVpnNetwork == null) {
                findOurVpnNetwork()?.let { considerVpnNetwork(it, "allNetworks") }
                if (ourVpnNetwork != null || generation != vpnAttemptGeneration) return@launch
                val step =
                    when {
                        elapsed < 3_000 -> 150
                        elapsed < 20_000 -> 500
                        else -> 2_000
                    }
                delay(step.milliseconds)
                elapsed += step
                if (elapsed >= 60_000) {
                    log.w { "VPN network still missing after ${elapsed}ms; DNS stays black-holed" }
                    return@launch
                }
            }
        }
        synchronized(this) {
            if (generation != vpnAttemptGeneration) {
                job.cancel()
                return
            }
            vpnNetworkPollJob?.cancel()
            vpnNetworkPollJob = job
        }
    }

    private fun stopVpnNetworkPoll() {
        vpnNetworkPollJob?.cancel()
        vpnNetworkPollJob = null
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
        if (hevBridgeFd == null) {
            stopVpnNetworkPoll()
            ourVpnNetwork = null
            UnderlayDnsBridge.setVpnNetwork(null)
        }
    }

    override fun startHevSocks5Bridge(port: Int, password: String) {
        hevBridgeTarget = HevBridgeTarget(port, password)
        if (hevBridgeJob != null) return
        hevBridgeJob = startHevBridge(port, password)
    }

    override fun stopHevSocks5Bridge() {
        stopHevNative()
        hevBridgeTarget = null
    }

    // Stop HEV without dropping the live SOCKS target so a KS TUN replace can reattach.
    private fun stopHevNative() {
        hevBridgeJob?.cancel()
        hevBridgeJob = null

        // TProxyService is an object with a System.loadLibrary init block, so merely
        // referencing it loads the native lib. Every VPN teardown runs through here even
        // when HEV was never started, so skip the call entirely unless a bridge target was
        // actually set
        if (hevBridgeTarget == null) return

        try {
            TProxyService.TProxyStopService()
        } catch (e: Throwable) {
            // Catches Throwable, not just Exception as a damaged/stale split install can throw
            // UnsatisfiedLinkError (an Error) on first touch of TProxyService, and that must
            // never crash teardown.
            log.w(e) { "TProxyStopService failed, may already be stopped" }
        }
    }

    private fun rebindHevSocks5Bridge() {
        val target = hevBridgeTarget ?: return
        if (hevBridgeFd == null) {
            log.w { "Cannot rebind HEV: kill switch fd is missing" }
            return
        }
        log.d { "Rebinding HEV bridge to new kill switch fd on SOCKS port ${target.port}" }
        hevBridgeJob = startHevBridge(target.port, target.password)
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

        private data class HevBridgeTarget(val port: Int, val password: String)

        private const val LOCKDOWN_SESSION_NAME = "Lockdown"
        private const val LOCALHOST = "127.0.0.1"
        private const val IPV4_INTERFACE_ADDRESS = "10.0.0.1"
        private const val IPV6_INTERFACE_ADDRESS = "2001:db8::1"
        const val LOCKDOWN_USERNAME = "local"
        private const val IPV4_DEFAULT_ROUTE = "0.0.0.0"
        private const val IPV6_DEFAULT_ROUTE = "::"
    }
}
