package com.wgtunnel.backend

import co.touchlab.kermit.Logger
import co.touchlab.kermit.Severity

enum class LogLevel {
    Verbose,
    Debug,
    Info,
    Warn,
    Error,
}

object BackendLog {
    @Volatile private var configured = false

    fun setMinLevel(level: LogLevel) {
        Logger.setMinSeverity(level.toSeverity())
        configured = true
    }

    internal fun applyDefaultIfNeeded() {
        if (!configured) setMinLevel(LogLevel.Info)
    }

    private fun LogLevel.toSeverity(): Severity =
        when (this) {
            LogLevel.Verbose -> Severity.Verbose
            LogLevel.Debug -> Severity.Debug
            LogLevel.Info -> Severity.Info
            LogLevel.Warn -> Severity.Warn
            LogLevel.Error -> Severity.Error
        }
}
