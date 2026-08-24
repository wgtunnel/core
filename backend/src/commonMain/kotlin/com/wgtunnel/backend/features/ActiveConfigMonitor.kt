package com.wgtunnel.backend.features

import co.touchlab.kermit.Logger
import com.wgtunnel.parser.ActiveConfig
import kotlin.time.Duration
import kotlinx.coroutines.*

internal class ActiveConfigMonitor(
    private val tunnelId: Int,
    private val host: Host,
) {

    val log = Logger.withTag("ActiveConfigMonitor")

    interface Host {
        suspend fun getActiveConfig(): ActiveConfig?

        fun updateActiveConfig(config: ActiveConfig?)

        fun isEnabled(): Boolean

        fun interval(): Duration
    }

    fun start(scope: CoroutineScope): Job = scope.launch {
        log.i { "Stats monitor job started for tunnel $tunnelId" }
        var enabled = false
        var interval = Duration.ZERO
        var consecutiveMisses = 0
        while (isActive) {
            val nowEnabled = host.isEnabled()
            val nowInterval = host.interval()
            if (nowEnabled != enabled) {
                enabled = nowEnabled
                if (enabled) {
                    log.i {
                        "Stats monitor enabled for tunnel $tunnelId " +
                            "(interval=${nowInterval.inWholeSeconds}s)"
                    }
                } else {
                    log.i { "Stats monitor disabled for tunnel $tunnelId" }
                }
            } else if (enabled && nowInterval != interval && interval != Duration.ZERO) {
                log.i {
                    "Stats monitor interval ${interval.inWholeSeconds}s → " +
                        "${nowInterval.inWholeSeconds}s for tunnel $tunnelId"
                }
            }
            interval = nowInterval

            if (!nowEnabled) {
                delay(nowInterval)
                continue
            }
            val config = host.getActiveConfig()
            if (config == null) {
                // During bounce/restart we don't tear down monitor
                consecutiveMisses++
                if (consecutiveMisses == 1 || consecutiveMisses % 10 == 0) {
                    log.w {
                        "no handle/config for tunnel $tunnelId (miss $consecutiveMisses), retrying"
                    }
                }
                delay(nowInterval)
                continue
            }
            consecutiveMisses = 0
            host.updateActiveConfig(config)
            delay(nowInterval)
        }
    }
}
