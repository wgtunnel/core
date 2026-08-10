package com.wgtunnel.backend.shell

import co.touchlab.kermit.Logger
import com.topjohnwu.superuser.Shell

actual class ShellExecutor {

    actual fun run(command: String): ShellResult {
        return try {
            val result = Shell.cmd(command).exec()
            log.d { "Root command exit=${result.code}" }
            ShellResult(
                code = result.code,
                stdout = result.out,
                stderr = result.err,
            )
        } catch (e: Exception) {
            log.e(e) { "Root command failed: $command" }
            throw e
        }
    }

    actual companion object {
        private val log = Logger.withTag("ShellExecutor")

        actual fun hasPrivilegedAccess(): Boolean = Shell.isAppGrantedRoot() == true

        actual fun requestPrivilegedAccess(): Boolean =
            try {
                Shell.cmd("su").exec().isSuccess
            } catch (e: Exception) {
                log.e(e) { "Root permission request failed" }
                false
            }
    }
}
