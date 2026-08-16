package com.wgtunnel.backend

import co.touchlab.kermit.Logger
import com.wgtunnel.backend.dns.CustomDnsResolver
import com.wgtunnel.backend.dns.EndpointResolver
import com.wgtunnel.backend.dns.SystemDnsResolver
import com.wgtunnel.backend.dns.UnderlayNetworkSynchronizer
import com.wgtunnel.backend.enums.FamilyOverride
import com.wgtunnel.backend.event.TunnelEvent
import com.wgtunnel.backend.exception.BackendException
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
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
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
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

class TunnelBackend(
    private val scope: CoroutineScope,
    override val applicationProvider: ApplicationProvider,
    private val networkMonitor: NetworkMonitor,
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

    /**
     * Handles for which native start succeeded. stopVpn/turnProxyTunnelOff releases those; any
     * other reserved handle must be released via [releaseTunnelHandle].
     */
    private val nativeOwnedHandles = ConcurrentHashMap.newKeySet<Int>()

    init {
        loadBackendNativeLibrary()
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
            },
        )

    override fun onStatus(handle: Int, code: Int) {
        val state = Tunnel.State.fromNative(code)
        if (state == null) {
            log.w { "onStatus: unknown code=$code handle=$handle — acking" }
            ackStatus(handle, code)
            return
        }

        val tunnelId = byHandle[handle]
        if (tunnelId != null) {
            applyTransportState(tunnelId, state)
            log.d { "onStatus: applied handle=$handle code=$code tunnelId=$tunnelId state=$state" }
            ackStatus(handle, code)
            return
        }

        // Unmapped handle: nothing to apply. Ack so native stops re-notifying.
        log.w { "onStatus: unmapped handle=$handle code=$code state=$state — acking" }
        ackStatus(handle, code)
    }

    private fun applyTransportState(tunnelId: Int, state: Tunnel.State) {
        val current = _status.value.activeTunnels[tunnelId]?.transportState
        if (current != state) {
            log.i { "transportState tunnelId=$tunnelId $current → $state" }
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
                startEngineAndRegister(tunnel.id, mode, tunnelDnsConfig)
                if (scriptsEnabled) {
                    mode.config.`interface`.postUp?.let { runScripts(it, tunnel.id) }
                }
                tunnelJobs[tunnel.id] = startTunnelJobs(tunnel, mode)
            }
        }
            .onFailure { cleanup(tunnel.id) }
    }

    private suspend fun startEngineAndRegister(
        tunnelId: Int,
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig?,
    ): EngineStartResult =
        withContext(NonCancellable) {
            val handle = allocateTunnelHandle()
            if (handle < 0) {
                throw BackendException.InternalError("Failed to allocate tunnel handle")
            }

            // Map before native start so onStatus can apply immediately.
            byTunnelId[tunnelId]?.let { oldHandle ->
                if (oldHandle != handle) {
                    byHandle.remove(oldHandle)
                    abandonHandle(oldHandle)
                }
            }
            byHandle[handle] = tunnelId
            byTunnelId[tunnelId] = handle

            try {
                val result = engine.start(tunnelId, handle, mode, tunnelDnsConfig)
                nativeOwnedHandles.add(handle)
                updateActiveTunnel(tunnelId) {
                    it.copy(
                        interfaceName = result.interfaceName,
                        uptime = System.currentTimeMillis(),
                    )
                }
                result
            } catch (t: Throwable) {
                byHandle.remove(handle)
                byTunnelId.remove(tunnelId, handle)
                abandonHandle(handle)
                throw t
            }
        }

    // Release a handle that never transferred ownership to a running native tunnel.
    private fun abandonHandle(handle: Int) {
        if (nativeOwnedHandles.remove(handle)) {
            return
        }
        releaseTunnelHandle(handle)
    }

    private suspend fun bootstrapAndStart(
        tunnel: Tunnel,
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig? = null,
    ) {
        updateTunnelBootstrapState(tunnel.id, BootstrapState.ResolvingDns)
        log.i {
            "VPN: TUN is up (black-hole), resolving peer endpoints for ${tunnel.name} " +
                "before TurnOn"
        }

        val bootstrapResolution = endpointResolver.resolve(mode, tunnelDnsConfig)

        // select peer endpoint IP family based on network state and preference
        val networkHasIpv6 = networkMonitor.networkState.value?.hasIpv6 ?: false
        val familyOverride =
            if (tunnel.ipStrategy is Tunnel.IpStrategy.PreferIpv6 && networkHasIpv6) {
                FamilyOverride.ForceIpv6
            } else {
                FamilyOverride.ForceIpv4
            }
        log.i {
            "Endpoint family: strategy=${tunnel.ipStrategy::class.simpleName} " +
                "networkHasIpv6=$networkHasIpv6 → $familyOverride"
        }

        // No current endpoints yet, builds host map based on family preference
        val hostMap =
            bootstrapResolution.toHostMap(
                currentEndpoints = emptyMap(),
                familyOverride = familyOverride,
            )
        val runtimeMode = mode.rebuildModeWithHostMap(hostMap)
        mode.config.peers.forEach { peer ->
            val chosen = runtimeMode.config.peers.firstOrNull { it.publicKey == peer.publicKey }
            val resolved = hostMap[peer.publicKey]
            log.i {
                val key =
                    if (peer.publicKey.length <= 10) peer.publicKey
                    else "${peer.publicKey.take(4)}…${peer.publicKey.takeLast(4)}"
                "Using endpoint $key ${peer.endpoint} → ${chosen?.endpoint}" +
                    (resolved?.forcedPort?.let { " (ip4p port=$it)" } ?: "")
            }
        }

        updateActiveTunnel(tunnel.id) {
            it.copy(
                lastBootstrapResolution = bootstrapResolution,
                bootstrapState = BootstrapState.Complete,
            )
        }

        log.i { "VPN: bootstrap complete, bringing tunnel up (TurnOn) for ${tunnel.name}" }
        // pass our bootstrapped tunnel dns config
        startEngineAndRegister(tunnel.id, runtimeMode, bootstrapResolution.resolvedTunnelDnsConfig)
    }

    // Desktop TurnOn consumes a pending iface created before bootstrap. Stop
    // closes that TUN, so bounce must create it again. Android keeps the
    // VpnService fd across bounce.
    private suspend fun recreateVpnInterfaceIfNeeded(tunnel: Tunnel, mode: BackendMode) {
        if (mode !is BackendMode.Vpn || runtimeManager.vpnUsesOsTunFd) return
        runtimeManager.getOrCreateVpnRuntime().createTunInterface(tunnel, mode.config, false)
    }

    // Should only be called if mode config is static
    private suspend fun restartWithCurrentMode(
        handle: Int,
        tunnel: Tunnel,
        mode: BackendMode,
        dns: TunnelDnsConfig?,
    ): Boolean {
        stopNativeKeepMapped(handle, mode)
        recreateVpnInterfaceIfNeeded(tunnel, mode)
        startEngineAndRegister(tunnel.id, mode, dns)
        return true
    }

    /** Stop native tunnel and drop ownership; keep Kotlin maps until re-register. */
    private suspend fun stopNativeKeepMapped(handle: Int, mode: BackendMode) {
        nativeOwnedHandles.remove(handle)
        runCatching { engine.stop(handle, mode) }
            .onFailure { log.w(it) { "stopNativeKeepMapped: engine.stop failed handle=$handle" } }
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
        stopNativeKeepMapped(handle, mode)
        recreateVpnInterfaceIfNeeded(tunnel, runtimeMode)
        startEngineAndRegister(tunnel.id, runtimeMode, tunnelDnsConfig)
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
                log.w { "Bounce DNS timed out for tunnel ${tunnel.name}, bounce failed" }
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

        stopNativeKeepMapped(handle, mode)
        recreateVpnInterfaceIfNeeded(tunnel, runtimeMode)
        startEngineAndRegister(
            tunnel.id,
            runtimeMode,
            bootstrapResult.resolvedTunnelDnsConfig,
        )
        return true
    }

    override suspend fun bounceTunnelDevice(tunnelId: Int, withFreshResolution: Boolean): Boolean =
        tunnelMutex.withLock {
            val active = _status.value.activeTunnels[tunnelId] ?: return false
            val mode = active.mode ?: return false
            val tunnel = active.tunnel ?: return false
            val handle = byTunnelId[tunnel.id] ?: return false

            val runtimeTunnelDnsConfig = active.getRuntimeTunnelDnsConfig()

            return try {
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
            } catch (t: CancellationException) {
                throw t
            } catch (t: Throwable) {
                log.e(t) { "Tunnel bounce failed for $tunnelId" }
                false
            }
        }

    private fun startTunnelBootstrapJob(
        tunnel: Tunnel,
        mode: BackendMode,
        tunnelDnsConfig: TunnelDnsConfig? = null,
    ): Job {
        val job = scope.launch {
            try {
                bootstrapAndStart(tunnel, mode, tunnelDnsConfig)
                val scriptsEnabled = tunnel.scriptsEnabled
                if (scriptsEnabled) {
                    mode.config.`interface`.postUp?.let { runScripts(it, tunnel.id) }
                }

                tunnelJobs[tunnel.id] = startTunnelJobs(tunnel, mode)
            } catch (t: CancellationException) {
                log.d { "Bootstrap job cancelled for tunnel ${tunnel.id}" }
                // startEngineAndRegister is NonCancellable, a cancel after native start must
                // still tear the device down
                withContext(NonCancellable) {
                    tearDownIfRegistered(tunnel.id, mode)
                    cleanup(tunnel.id)
                }
                throw t
            } catch (t: Throwable) {
                log.e(t) { "Tunnel bootstrap failed for ${tunnel.id}" }
                withContext(NonCancellable) {
                    tearDownIfRegistered(tunnel.id, mode)
                    cleanup(tunnel.id)
                }
            } finally {
                pendingResolutionJobs.remove(tunnel.id, coroutineContext.job)
            }
        }
        return job
    }

    /**
     * Stop native device if this tunnel already has a mapped handle, and drop handle maps. Safe to
     * call when cleanup has already run.
     */
    private suspend fun tearDownIfRegistered(tunnelId: Int, mode: BackendMode) {
        val handle = byTunnelId[tunnelId] ?: return
        stopAndReleaseHandle(handle, mode, tunnelId)
    }

    /**
     * Stop native if it owns tunnel handle, otherwise release the reservation. Always clears maps.
     */
    private suspend fun stopAndReleaseHandle(handle: Int, mode: BackendMode?, tunnelId: Int) {
        byHandle.remove(handle)
        byTunnelId.remove(tunnelId, handle)
        val nativeOwned = nativeOwnedHandles.remove(handle)
        when {
            nativeOwned && mode != null -> {
                runCatching { engine.stop(handle, mode) }
                    .onFailure {
                        log.w(it) {
                            "stopAndReleaseHandle: engine.stop failed for tunnel $tunnelId"
                        }
                        // Native may not have released, free the reservation defensively.
                        releaseTunnelHandle(handle)
                    }
            }
            nativeOwned && mode == null -> {
                log.w {
                    "stopAndReleaseHandle: native-owned handle=$handle tunnel=$tunnelId with no mode"
                }
                releaseTunnelHandle(handle)
            }
            else -> releaseTunnelHandle(handle)
        }
    }

    private suspend fun setupServicesAndProtectorForMode(
        tunnel: Tunnel,
        mode: BackendMode,
        fakeDns: Boolean,
    ) {
        when (mode) {
            is BackendMode.Proxy.KillSwitchPrimary -> {
                runtimeManager.getOrCreateVpnRuntime()
                runtimeManager.setKillSwitch(mode.killSwitchConfig)
            }
            is BackendMode.Proxy.Standard -> {
                runtimeManager.getOrCreateTunnelRuntime()
            }
            is BackendMode.Vpn -> {
                log.i {
                    "VPN: creating TUN/routes/firewall (black-hole) before bootstrap " +
                        "for ${tunnel.name} (id=${tunnel.id})"
                }
                val vpn = runtimeManager.getOrCreateVpnRuntime()
                vpn.createTunInterface(tunnel, mode.config, fakeDns)
            }
        }
    }

    private suspend fun cleanup(tunnelId: Int) {
        // Cancel only as cleanup may run from that job
        pendingResolutionJobs.remove(tunnelId)?.cancel()
        tunnelJobs.remove(tunnelId)?.cancel()

        val activeTunnels = _status.value.activeTunnels
        val active = activeTunnels[tunnelId]
        val mode = active?.mode

        val proxyTypeCount = activeTunnels.values.count { it.mode is BackendMode.Proxy.Standard }

        val handle = byTunnelId[tunnelId]
        if (handle != null) {
            stopAndReleaseHandle(handle, mode, tunnelId)
        }

        removeActiveTunnel(tunnelId)

        // VPN mode owns the TUN / VpnService session. Kill switch is independent
        // and must not be started or stopped here (including KillSwitchPrimary).
        if (mode is BackendMode.Vpn) {
            runtimeManager.destroyVpnRuntime(listOf(tunnelId))
        }
        if (proxyTypeCount == 1) {
            runtimeManager.destroyTunnelRuntime()
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

        // Bootstrap runs outside the start() mutex. Cancel and join so
        // start never maps a handle or startEngineAndRegister finishes and byTunnelId is set so we
        // can stop engine and prevent orphaned tunnels.
        val bootstrapJob = pendingResolutionJobs.remove(tunnelId)
        if (bootstrapJob != null) {
            bootstrapJob.cancel()
            bootstrapJob.join()
        }

        val handle = byTunnelId[tunnelId]
        val mode = activeTunnel.mode ?: _status.value.activeTunnels[tunnelId]?.mode
        val scriptsEnabled = activeTunnel.tunnel?.scriptsEnabled == true

        try {
            if (handle != null && mode != null && scriptsEnabled) {
                mode.config.`interface`.preDown?.let { runScripts(it, tunnelId) }
            }
            // cleanup() stops native / releases the handle reservation once.
            if (handle == null) {
                log.d {
                    "stopTunnel: no native handle for tunnel $tunnelId (start had not registered)"
                }
            }
        } finally {
            cleanup(tunnelId)
            if (handle != null && mode != null && scriptsEnabled) {
                mode.config.`interface`.postDown?.let { runScripts(it, tunnelId) }
            }
        }
    }

    override suspend fun setKillSwitch(config: KillSwitchConfig) = runCatching {
        runtimeManager.setKillSwitch(config)
        _status.update { current ->
            current.copy(
                killSwitch = current.killSwitch.copy(enabled = true, config = config),
                activeTunnels =
                    current.activeTunnels.mapValues { (_, tunnel) ->
                        val mode = tunnel.mode
                        if (mode is BackendMode.Proxy.KillSwitchPrimary) {
                            tunnel.copy(mode = mode.copy(killSwitchConfig = config))
                        } else {
                            tunnel
                        }
                    },
            )
        }
    }

    override suspend fun disableKillSwitch() = runCatching {
        runtimeManager.setKillSwitch(null)
        _status.update {
            it.copy(
                killSwitch =
                    KillSwitchState(
                        enabled = false,
                        config = null,
                        primaryTunnel = it.killSwitch.primaryTunnel,
                    )
            )
        }
    }

    override suspend fun setBootstrapDnsMode(mode: DnsBoostrapMode) {
        _status.update { it.copy(dnsMode = mode) }
        log.d { "DNS Bootstrap mode set to: $mode" }
    }

    override suspend fun stopAllActiveTunnels() = tunnelMutex.withLock {
        val vpnIds =
            _status.value.activeTunnels
                .filter { it.value.mode is BackendMode.Vpn }
                .mapNotNull { it.value.tunnel?.id }
        _status.value.activeTunnels.forEach { (id, tunnel) -> stopTunnelInternal(id, tunnel) }
        applicationProvider.refreshStatusUi()
        runtimeManager.destroyTunnelRuntime()
        runtimeManager.destroyVpnRuntime(vpnIds)
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
                                    failureThreshold =
                                        TunnelRecovery.TUNNEL_HEALTH_STABILIZE_WINDOW_MILLIS
                                            .milliseconds,
                                    stabilizeWindow =
                                        TunnelRecovery.TUNNEL_HEALTH_STABILIZE_WINDOW_MILLIS
                                            .milliseconds,
                                    host =
                                        object : TunnelRecovery.Host {
                                            override fun observe(): Flow<TunnelRecovery.Snapshot> =
                                                combine(
                                                        status.mapNotNull {
                                                            it.activeTunnels[tunnel.id]
                                                        },
                                                        networkMonitor.networkState.filterNotNull(),
                                                        powerManager.deviceAwake,
                                                    ) { active, network, awake ->
                                                        TunnelRecovery.Snapshot(
                                                            shouldRecoveryBeActive =
                                                                active.shouldRecoveryBeActive(
                                                                    network.isUsable
                                                                ),
                                                            bootstrapPending =
                                                                active.bootstrapState is
                                                                    BootstrapState.ResolvingDns ||
                                                                    active.bootstrapState is
                                                                        BootstrapState.UpdatingPeers,
                                                            lastResolvedPeers =
                                                                active.lastBootstrapResolution
                                                                    ?.peerKeyResults,
                                                            networkHasIpv6 = network.hasIpv6,
                                                            activeNetworkKey = network.key,
                                                            deviceAwake = awake,
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

    // Tells native that Kotlin applied status for the tunnel handle
    external fun ackStatus(handle: Int, code: Int)

    // Reserve a free native tunnel handle before start so status can be mapped first.
    external fun allocateTunnelHandle(): Int

    // Free a reserved handle that never became a running native tunnel.
    external fun releaseTunnelHandle(handle: Int)
}
