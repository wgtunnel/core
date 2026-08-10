package com.wgtunnel.backend

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.dns.CustomDnsResolver
import com.wgtunnel.backend.dns.EndpointResolver
import com.wgtunnel.backend.dns.SystemDnsResolver
import com.wgtunnel.backend.dns.UnderlayNetworkSynchronizer
import com.wgtunnel.backend.enums.FamilyOverride
import com.wgtunnel.backend.event.TunnelEvent
import com.wgtunnel.backend.exception.ShellException
import com.wgtunnel.backend.features.ActiveConfigMonitor
import com.wgtunnel.backend.features.TunnelRecovery
import com.wgtunnel.backend.model.BackendMode
import com.wgtunnel.backend.model.EngineStartResult
import com.wgtunnel.backend.model.KillSwitchConfig
import com.wgtunnel.backend.model.dns.BootstrapResolution
import com.wgtunnel.backend.model.dns.DnsBoostrapMode
import com.wgtunnel.backend.model.dns.TunnelDnsConfig
import com.wgtunnel.backend.service.RuntimeManager
import com.wgtunnel.backend.shell.ShellExecutor
import com.wgtunnel.backend.state.ActiveTunnel
import com.wgtunnel.backend.state.BackendStatus
import com.wgtunnel.backend.state.BootstrapState
import com.wgtunnel.backend.state.KillSwitchState
import com.wgtunnel.backend.system.NetworkMonitor
import com.wgtunnel.backend.system.PowerManager
import com.wgtunnel.backend.util.hasDynamicEndpoints
import com.wgtunnel.backend.util.rebuildModeWithHostMap
import com.wgtunnel.backend.util.withEndpointsFrom
import com.wgtunnel.parser.ActiveConfig
import com.wgtunnel.parser.PeerSection
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

class TunnelBackend(
    private val scope: CoroutineScope,
    override val applicationProvider: ApplicationProvider,
    private val networkMonitor: NetworkMonitor
) : Backend, TunnelStatusCallback {

    private val log = Logger.withTag("TunnelBackend")
    private val runtimeManager = RuntimeManager(applicationProvider)
    private val engine: TunnelEngine = WireGuardTunnelEngine(runtimeManager)
    private val shellExecutor by lazy { ShellExecutor() }
    private val powerManager: PowerManager = PowerManager(applicationProvider)
    private val systemDnsResolver = SystemDnsResolver(networkMonitor)

    private val _status = MutableStateFlow(BackendStatus())
    override val status: Flow<BackendStatus> = _status.asStateFlow()

    private val _events = MutableSharedFlow<TunnelEvent>(extraBufferCapacity = 32)
    override val events = _events.asSharedFlow()

    private val tunnelMutex = Mutex()

    private val tunnelJobs = ConcurrentHashMap<Int, Job>()
    private val byHandle = ConcurrentHashMap<Int, Int>()
    private val byTunnelId = ConcurrentHashMap<Int, Int>()
    private val pendingResolutionJobs = ConcurrentHashMap<Int, Job>()

    init {
        System.loadLibrary("am-go")
        BackendRuntime.install(runtimeManager, this, applicationProvider)
        setStatusCallback(this)
        UnderlayNetworkSynchronizer(networkMonitor, scope)
    }

    private val endpointResolver =
        EndpointResolver(
            networkMonitor = networkMonitor,
            systemDns = systemDnsResolver,
            getDnsMode = { _status.value.dnsMode },
            isKillSwitchEnabled = { _status.value.killSwitch.enabled },
            createCustomResolver = { config, bypass ->
                CustomDnsResolver(config, bypass, systemDnsResolver)
            }
        )


    override fun onStatus(handle: Int, code: Int) {
        val state = Tunnel.State.fromNative(code) ?: return
        val tunnelId = byHandle[handle] ?: return
        val current = _status.value.activeTunnels[tunnelId]?.transportState
        if (current != state) {
            updateTunnelTransportState(tunnelId, state)
        }
    }

    override suspend fun start(
        tunnel: Tunnel,
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig?,
    ): Result<Unit> = tunnelMutex.withLock {
        runCatching {
            if (_status.value.activeTunnels.containsKey(tunnel.id)) {
                log.w { "Tunnel ${tunnel.id} already running" }
                return@runCatching
            }

            addOrReplaceActiveTunnel(
                tunnel.id,
                ActiveTunnel(
                    tunnel = tunnel,
                    transportState = Tunnel.State.Starting,
                    mode = mode,
                    tunnelDnsConfig = tunnelDnsConfig,
                ),
            )
            applicationProvider.refreshStatusUi()

            val scriptsEnabled = tunnel.scriptsEnabled

            if (scriptsEnabled) mode.config.`interface`.preUp?.let { runScripts(it, tunnel.id) }

            val useFakeDns = tunnelDnsConfig != null || mode is BackendMode.Proxy.KillSwitchPrimary

            setupServicesAndProtectorForMode(tunnel, mode, useFakeDns)

            if (needsBootstrap(mode, tunnelDnsConfig)) {
                pendingResolutionJobs[tunnel.id] =
                    startTunnelBootstrapJob(tunnel, mode, tunnelDnsConfig)
            } else {
                val result = engine.start(tunnel.id, mode, tunnelDnsConfig)
                onEngineStartResult(tunnel.id, result)
                if (scriptsEnabled) {
                    mode.config.`interface`.postUp?.let { runScripts(it, tunnel.id) }
                }
                tunnelJobs[tunnel.id] = startTunnelJobs(tunnel, mode)
            }
        }
            .onFailure { cleanup(tunnel.id) }
    }

    private suspend fun bootstrapAndStart(
        tunnel: Tunnel,
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig? = null,
    ) {
        updateTunnelBootstrapState(tunnel.id, BootstrapState.ResolvingDns)

        val bootstrapResolution = endpointResolver.resolve(mode, tunnelDnsConfig)

        // select peer endpoint IP family based on network state and preference
        val networkHasIpv6 = networkMonitor.networkState.value?.hasIpv6 ?: false
        val familyOverride =
            if (tunnel.ipStrategy is Tunnel.IpStrategy.PreferIpv6 && networkHasIpv6) {
                FamilyOverride.ForceIpv6
            } else {
                FamilyOverride.ForceIpv4
            }

        // No current endpoints yet, builds host map based on family preference
        val hostMap =
            bootstrapResolution.toHostMap(
                currentEndpoints = emptyMap(),
                familyOverride = familyOverride,
            )
        val runtimeMode = mode.rebuildModeWithHostMap(hostMap)

        updateActiveTunnel(tunnel.id) {
            it.copy(
                lastBootstrapResolution = bootstrapResolution,
                bootstrapState = BootstrapState.Complete,
            )
        }

        // pass our bootstrapped tunnel dns config
        val result =
            engine.start(tunnel.id, runtimeMode, bootstrapResolution.resolvedTunnelDnsConfig)
        onEngineStartResult(tunnel.id, result)
    }

    // Should only be called if mode config is static
    private suspend fun restartWithCurrentMode(
        handle: Int,
        tunnel: Tunnel,
        mode: BackendMode,
        dns: TunnelDnsConfig?,
    ): Boolean {
        engine.stop(handle, mode)
        val result = engine.start(tunnel.id, mode, dns)
        onEngineStartResult(tunnel.id, result)
        return true
    }

    private suspend fun bounceActiveConfig(
        handle: Int,
        tunnel: Tunnel,
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig?,
    ): Boolean {

        val activeConfig =
            engine.getActiveConfig(handle, mode)
                ?: run {
                    log.w {
                    "Unable to get active config for ${tunnel.name} for bounce, stopping bounce"
                    }
                    return false
                }

        val runtimeMode = mode.withEndpointsFrom(activeConfig)
        engine.stop(handle, mode)
        val result = engine.start(tunnel.id, runtimeMode, tunnelDnsConfig)
        onEngineStartResult(tunnel.id, result)
        return true
    }

    private suspend fun bounceWithFreshDns(
        handle: Int,
        tunnel: Tunnel,
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig?,
    ): Boolean {
        val bootstrapResult =
            try {
                withTimeout(10.seconds) {
                    // reuse the cached resolve tunnelDnsConfig
                    endpointResolver.resolve(mode, tunnelDnsConfig)
                }
            } catch (_: TimeoutCancellationException) {
                log.w {"Bounce DNS timed out for tunnel ${tunnel.name}, bounce failed" }
                return false
            }

        val currentActiveConfig =
            engine.getActiveConfig(handle, mode)
                ?: run {
                    log.w {
                        "Failed to get the current active config for ${tunnel.name}, stopping the fresh DDNS bounce"
                    }
                    return false
                }

        val currentEndpoints = currentActiveConfig.peers.associate { it.publicKey to it.endpoint }

        val hostMap =
            bootstrapResult.toHostMap(
                currentEndpoints = currentEndpoints,
                familyOverride = FamilyOverride.MatchCurrent,
            )
        val runtimeMode = mode.rebuildModeWithHostMap(hostMap)

        updateActiveTunnel(tunnel.id) {
            it.copy(
                bootstrapState = BootstrapState.Complete,
                lastBootstrapResolution = bootstrapResult,
            )
        }

        engine.stop(handle, mode)
        val result = engine.start(tunnel.id, runtimeMode, bootstrapResult.resolvedTunnelDnsConfig)
        onEngineStartResult(tunnel.id, result)
        return true
    }

    override suspend fun bounceTunnelDevice(tunnelId: Int, withFreshResolution: Boolean): Boolean =
        tunnelMutex.withLock {
            val active = _status.value.activeTunnels[tunnelId] ?: return false
            val mode = active.mode ?: return false
            val tunnel = active.tunnel ?: return false
            val handle = byTunnelId[tunnel.id] ?: return false

            val runtimeTunnelDnsConfig = active.getRuntimeTunnelDnsConfig()

            val bounced =
                when {
                    !mode.config.hasDynamicEndpoints() -> {
                        restartWithCurrentMode(handle, tunnel, mode, runtimeTunnelDnsConfig)
                    }
                    !withFreshResolution -> {
                        bounceActiveConfig(handle, tunnel, mode, runtimeTunnelDnsConfig)
                    }
                    else -> {
                        bounceWithFreshDns(handle, tunnel, mode, runtimeTunnelDnsConfig)
                    }
                }
            if (bounced) {
                _events.emit(TunnelEvent.SeamlessRecoveryAttempted(tunnelId))
            }
            return bounced
        }

    private fun startTunnelBootstrapJob(
        tunnel: Tunnel,
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig? = null,
    ) = scope.launch {
        try {
            bootstrapAndStart(tunnel, mode, tunnelDnsConfig)
            val scriptsEnabled = tunnel.scriptsEnabled
            if (scriptsEnabled) {
                mode.config.`interface`.postUp?.let { runScripts(it, tunnel.id) }
            }

            tunnelJobs[tunnel.id] = startTunnelJobs(tunnel, mode)
        } catch (t: Throwable) {
            if (t is CancellationException) {
                log.d { "Bootstrap job cancelled for tunnel ${tunnel.id}" }
            } else {
                log.e(t) { "Tunnel bootstrap failed for ${tunnel.id}" }
                cleanup(tunnel.id)
            }
            if (t is CancellationException) throw t
        }
    }

    private suspend fun setupServicesAndProtectorForMode(
        tunnel: Tunnel,
        mode: BackendMode,
        fakeDns: Boolean,
    ) {
        when (mode) {
            is BackendMode.Proxy.KillSwitchPrimary -> {
                runtimeManager.ensureVpnReady()
                runtimeManager.setKillSwitch(mode.killSwitchConfig)
            }
            is BackendMode.Proxy.Standard -> {
                runtimeManager.getTunnelService()
            }
            is BackendMode.Vpn -> {
                val vpn = runtimeManager.ensureVpnReady()
                vpn.createTunInterface(tunnel, mode.config, fakeDns)
            }
        }
    }

    private fun onEngineStartResult(tunnelId: Int, result: EngineStartResult) {
        // old handle should be removed if exists
        byTunnelId[tunnelId]?.let { oldHandle ->
            if (oldHandle != result.handle) {
                byHandle.remove(oldHandle)
            }
        }
        updateActiveTunnel(tunnelId) {
            it.copy(interfaceName = result.interfaceName, uptime = System.currentTimeMillis())
        }
        byHandle[result.handle] = tunnelId
        byTunnelId[tunnelId] = result.handle
    }

    private suspend fun cleanup(tunnelId: Int) {
        pendingResolutionJobs.remove(tunnelId)?.cancel()
        tunnelJobs.remove(tunnelId)?.cancel()

        val activeTunnels = _status.value.activeTunnels

        val vpnTypeCount = activeTunnels.values.count { it.mode is BackendMode.Vpn }

        val proxyTypeCount = activeTunnels.values.count { it.mode is BackendMode.Proxy.Standard }

        removeActiveTunnel(tunnelId)
        byTunnelId[tunnelId]?.let { byHandle.remove(it) }
        byTunnelId.remove(tunnelId)

        if (vpnTypeCount == 1 && !_status.value.killSwitch.enabled) {
            runtimeManager.ensureVpnShutdown()
        }
        if (proxyTypeCount == 1) {
            runtimeManager.stopTunnelService()
        }
    }

    private suspend fun runScripts(commands: List<String>, tunnelId: Int) {
        try {
            commands.forEach { cmd ->
                withTimeout(3_000L.milliseconds) {
                    withContext(Dispatchers.IO) { shellExecutor.run(cmd) }
                }
            }
        } catch (t: Throwable) {
            log.w(t) { "Shell commands failed" }
            if (t is ShellException.NoAccess) {
                _events.emit(TunnelEvent.NoRootShellAccess(tunnelId = tunnelId))
            }
        }
    }

    override suspend fun stop(id: Int): Result<Unit> = tunnelMutex.withLock {
        runCatching {
            val activeTun = _status.value.activeTunnels[id] ?: return@runCatching
            updateTunnelTransportState(id, Tunnel.State.Stopping)
            try {
                stopTunnelInternal(id, activeTun)
            } finally {
                applicationProvider.refreshStatusUi()
            }
        }
    }

    private suspend fun stopTunnelInternal(tunnelId: Int, activeTunnel: ActiveTunnel) {
        updateTunnelTransportState(tunnelId, Tunnel.State.Stopping)

        val handle = byTunnelId[tunnelId]

        if (handle == null) {
            cleanup(tunnelId)
            return
        }

        val scriptsEnabled = activeTunnel.tunnel?.scriptsEnabled == true
        val mode = activeTunnel.mode ?: return

        try {
            if (scriptsEnabled) mode.config.`interface`.preDown?.let { runScripts(it, tunnelId) }
            engine.stop(handle, activeTunnel.mode)
            if (scriptsEnabled) mode.config.`interface`.postDown?.let { runScripts(it, tunnelId) }
        } finally {
            cleanup(tunnelId)
        }
    }

    override suspend fun setKillSwitch(config: KillSwitchConfig) = runCatching {
        runtimeManager.setKillSwitch(config)
        _status.update {
            it.copy(killSwitch = it.killSwitch.copy(enabled = true, config = config))
        }
    }

    override suspend fun disableKillSwitch() = runCatching {
        runtimeManager.setKillSwitch(null)
        _status.update {
            it.copy(
                killSwitch = KillSwitchState(
                    enabled = false,
                    config = null,
                    primaryTunnel = it.killSwitch.primaryTunnel,
                ),
            )
        }
    }

    override suspend fun setBootstrapDnsMode(mode: DnsBoostrapMode) {
        _status.update { it.copy(dnsMode = mode) }
        log.d { "DNS Bootstrap mode set to: $mode" }
    }

    override suspend fun stopAllActiveTunnels() = tunnelMutex.withLock {
        _status.value.activeTunnels.forEach { (id, tunnel) -> stopTunnelInternal(id, tunnel) }
        applicationProvider.refreshStatusUi()
        runtimeManager.stopTunnelService()
        if (!_status.value.killSwitch.enabled) {
            runtimeManager.stopVpnService()
            runtimeManager.stopCompanionService()
        }
        Result.success(Unit)
    }

    private fun updateStatus(transform: (BackendStatus) -> BackendStatus) {
        _status.update(transform)
    }

    fun addOrReplaceActiveTunnel(id: Int, tunnel: ActiveTunnel) {
        updateStatus { current ->
            current.copy(activeTunnels = current.activeTunnels + (id to tunnel))
        }
    }

    fun updateActiveTunnel(id: Int, transform: (ActiveTunnel) -> ActiveTunnel) {
        updateStatus { current ->
            val existing = current.activeTunnels[id] ?: return@updateStatus current
            current.copy(activeTunnels = current.activeTunnels + (id to transform(existing)))
        }
    }

    fun removeActiveTunnel(id: Int) {
        updateStatus { current -> current.copy(activeTunnels = current.activeTunnels - id) }
    }

    fun updateTunnelTransportState(id: Int, newState: Tunnel.State) {
        updateActiveTunnel(id) { tunnel ->
            val stateChanged = tunnel.transportState != newState
            tunnel.copy(
                transportState = newState,
                lastHealthChangeMs =
                    if (stateChanged || tunnel.lastHealthChangeMs == 0L) {
                        System.currentTimeMillis()
                    } else {
                        tunnel.lastHealthChangeMs
                    },
            )
        }
    }

    private fun needsBootstrap(mode: BackendMode, cfg: TunnelDnsConfig?): Boolean =
        mode.config.hasDynamicEndpoints() || (cfg?.needsResolve() == true)

    fun updateTunnelBootstrapState(id: Int, newState: BootstrapState) {
        updateActiveTunnel(id) { tunnel -> tunnel.copy(bootstrapState = newState) }
    }

    private fun startTunnelJobs(tunnel: Tunnel, mode: BackendMode): Job {
        return scope.launch {
            supervisorScope {
                tunnel.features.forEach { feature ->
                    when (feature) {
                        is Tunnel.Feature.ActiveConfigMonitor -> {
                            val monitor =
                                ActiveConfigMonitor(
                                    tunnelId = tunnel.id,
                                    interval = feature.intervalSeconds.seconds,
                                    host =
                                        object : ActiveConfigMonitor.Host {
                                            override suspend fun getActiveConfig(): ActiveConfig? {
                                                val handle = byTunnelId[tunnel.id] ?: return null
                                                return engine.getActiveConfig(handle, mode)
                                            }

                                            override fun updateActiveConfig(config: ActiveConfig?) {
                                                updateActiveTunnel(tunnel.id) {
                                                    it.copy(activeConfig = config)
                                                }
                                            }
                                        },
                                )
                            monitor.start(this)
                        }
                        is Tunnel.Feature.Recovery -> {
                            val hasDynamicEndpoints = mode.config.hasDynamicEndpoints()
                            val recovery =
                                TunnelRecovery(
                                    powerManager = powerManager,
                                    tunnelId = tunnel.id,
                                    mode = mode,
                                    recovery =
                                        feature.copy(
                                            dynamicDnsRecovery =
                                                feature.dynamicDnsRecovery && hasDynamicEndpoints,
                                            ipv6Recovery =
                                                hasDynamicEndpoints &&
                                                        (tunnel.ipStrategy
                                                                as? Tunnel.IpStrategy.PreferIpv6)
                                                            ?.recoveryEnabled ?: false,
                                            ipv4Fallback =
                                                hasDynamicEndpoints &&
                                                        tunnel.ipStrategy is
                                                                Tunnel.IpStrategy.PreferIpv6,
                                        ),
                                    failureThreshold = TUNNEL_FAILURE_THRESHOLD_MILLIS.milliseconds,
                                    stabilizeWindow =
                                        TUNNEL_HEALTH_STABILIZE_WINDOW_MILLIS.milliseconds,
                                    host =
                                        object : TunnelRecovery.Host {
                                            override fun observe(): Flow<TunnelRecovery.Snapshot> =
                                                combine(
                                                    status.mapNotNull {
                                                        it.activeTunnels[tunnel.id]
                                                    },
                                                    networkMonitor.networkState
                                                        .filterNotNull(),
                                                ) { active, network ->
                                                    TunnelRecovery.Snapshot(
                                                        transportState = active.transportState,
                                                        lastResolvedPeers =
                                                            active.lastBootstrapResolution
                                                                ?.peerKeyResults,
                                                        networkUsable = network.isUsable,
                                                        networkHasIpv6 = network.hasIpv6,
                                                        activeNetworkKey = network.key,
                                                    )
                                                }
                                                    .distinctUntilChanged()

                                            override suspend fun getActiveConfig(): ActiveConfig? {
                                                val handle = byTunnelId[tunnel.id] ?: return null
                                                return engine.getActiveConfig(handle, mode)
                                            }

                                            override suspend fun resolveFresh():
                                                    BootstrapResolution? {
                                                val active =
                                                    _status.value.activeTunnels[tunnel.id]
                                                        ?: return null
                                                val runtimeTunnelDnsConfig =
                                                    active.getRuntimeTunnelDnsConfig()
                                                return try {
                                                    withTimeout(10.seconds) {
                                                        endpointResolver.resolve(
                                                            mode,
                                                            runtimeTunnelDnsConfig,
                                                        )
                                                    }
                                                } catch (_: TimeoutCancellationException) {
                                                    log.w {
                                                        "Recovery Resolve: fresh peer resolve timed out for tunnel ${tunnel.id}"
                                                    }
                                                    null
                                                }
                                            }

                                            override suspend fun updatePeers(
                                                peers: List<PeerSection>
                                            ) {
                                                val handle = byTunnelId[tunnel.id] ?: return
                                                engine.updatePeers(handle, mode, peers)
                                            }

                                            override suspend fun bounce(
                                                withFreshResolution: Boolean
                                            ): Boolean {
                                                return bounceTunnelDevice(
                                                    tunnel.id,
                                                    withFreshResolution,
                                                )
                                            }

                                            override fun updateActiveTunnel(
                                                transform: (ActiveTunnel) -> ActiveTunnel
                                            ) {
                                                this@TunnelBackend.updateActiveTunnel(
                                                    tunnel.id,
                                                    transform,
                                                )
                                            }

                                            override suspend fun emit(event: TunnelEvent) {
                                                _events.emit(event)
                                            }
                                        },
                                )
                            recovery.start(this)
                        }
                    }
                }
                awaitCancellation()
            }
        }
    }

    external fun setStatusCallback(tunnelStatusCallback: TunnelStatusCallback?)

    companion object {
        private const val TUNNEL_FAILURE_THRESHOLD_MILLIS = 30_000L
        private const val TUNNEL_HEALTH_STABILIZE_WINDOW_MILLIS = 12_000L
    }
}
