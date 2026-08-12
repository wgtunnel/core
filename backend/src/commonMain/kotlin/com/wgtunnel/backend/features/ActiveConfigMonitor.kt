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
        var consecutiveMisses = 0
        while (isActive) {
            val config = host.getActiveConfig()
            if (config == null) {
                // During bounce/restart we don't tear down monitor
                consecutiveMisses++
                if (consecutiveMisses == 1 || consecutiveMisses % 10 == 0) {
                    log.w {
                        "no handle/config for tunnel $tunnelId (miss $consecutiveMisses), retrying"
                    }
                }
                delay(interval)
                continue
            }
            consecutiveMisses = 0
            host.updateActiveConfig(config)
            delay(interval)
        }
    }
}
