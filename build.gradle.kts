import com.ncorti.ktfmt.gradle.tasks.KtfmtFormatTask

plugins {
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
    alias(libs.plugins.kotlinMultiplatform) apply  false
    alias(libs.plugins.vanniktech.mavenPublish) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.jetbrains.kotlin.jvm) apply false
    alias(libs.plugins.ktfmt)
}

val jvmVersion = libs.versions.jvm.get().toInt()
version = libs.versions.lib.get()

allprojects {
    group = "com.wgtunnel"
    version = version
    plugins.withId("org.jetbrains.kotlin.jvm") {
        extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension> {
            jvmToolchain(jvmVersion)
        }
    }

    plugins.withId("org.jetbrains.kotlin.multiplatform") {
        extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension> {
            jvmToolchain(jvmVersion)
        }
    }
}


subprojects {
    apply {
        plugin(rootProject.libs.plugins.ktfmt.get().pluginId)
    }

    tasks.register<KtfmtFormatTask>("format") {
        source = project.fileTree(rootDir)
        include("**/*.kt")
        exclude("**/build/**", ".*generated.*", "**/winsw/**", "**/amneziawg-tools/**", "**/.gradle/**")
    }

    ktfmt {
        kotlinLangStyle()
    }
}