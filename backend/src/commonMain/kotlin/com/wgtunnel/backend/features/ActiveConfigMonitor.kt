package com.wgtunnel.backend.features

import co.touchlab.kermit.Logger
import com.wgtunnel.parser.ActiveConfig
import kotlin.time.Duration
import kotlinx.coroutines.*

internal class ActiveConfigMonitor(
    private val tunnelId: Int,
    private val interval: Duration,
    private val host: Host,
) {

    val log = Logger.withTag("ActiveConfigMonitor")

    interface Host {
        suspend fun getActiveConfig(): ActiveConfig?

        fun updateActiveConfig(config: ActiveConfig?)
    }

    fun start(scope: CoroutineScope): Job = scope.launch {
        while (isActive) {
            val config = host.getActiveConfig()
            if (config == null) {
                log.w { "no handle/config, stopping" }
                return@launch
            }
            host.updateActiveConfig(config)
            delay(interval)
        }
    }
}
