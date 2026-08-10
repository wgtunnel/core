package com.wgtunnel.backend.shell

expect class ShellExecutor() {
    fun run(command: String): ShellResult

    companion object {
        // Android only, desktop no-op
        fun requestPrivilegedAccess(): Boolean

        fun hasPrivilegedAccess(): Boolean
    }
}
