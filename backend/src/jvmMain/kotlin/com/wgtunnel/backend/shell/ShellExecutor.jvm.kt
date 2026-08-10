package com.wgtunnel.backend.shell

import co.touchlab.kermit.Logger
import java.util.concurrent.TimeUnit

actual class ShellExecutor {
    private val log = Logger.withTag("ShellExecutor")

    actual fun run(command: String): ShellResult {
        val os = System.getProperty("os.name").lowercase()
        val process =
            if (os.contains("win")) {
                    ProcessBuilder("cmd.exe", "/c", command)
                } else {
                    ProcessBuilder("sh", "-c", command)
                }
                .redirectErrorStream(false)
                .start()

        val stdout = process.inputStream.bufferedReader().readLines()
        val stderr = process.errorStream.bufferedReader().readLines()
        val finished = process.waitFor(30, TimeUnit.SECONDS)
        val code =
            if (finished) process.exitValue()
            else {
                process.destroyForcibly()
                -1
            }

        log.d { "Shell exit=$code cmd=$command" }
        return ShellResult(code = code, stdout = stdout, stderr = stderr)
    }

    actual companion object {
        // Assumes desktop is running as a root/admin daemon/service
        actual fun hasPrivilegedAccess(): Boolean = true

        actual fun requestPrivilegedAccess(): Boolean = true
    }
}
