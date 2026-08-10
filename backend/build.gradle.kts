plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.vanniktech.mavenPublish)
    alias(libs.plugins.kotlinxSerialization)
}

group = "com.wgtunnel"

kotlin {
    jvm()

    android {
        namespace = "com.wgtunnel.backend"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
        minSdk = libs.versions.android.minSdk.get().toInt()

        withJava() // enable java compilation support

        optimization {
            consumerKeepRules.apply {
                publish = true
                file("consumer-rules.pro")
            }
        }

        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }

    }

    sourceSets {
        androidMain.dependencies {
            implementation(project(":hevtunnel"))
            implementation(project(":backend-android"))
            implementation(libs.androidx.lifecycle.service)
            implementation(libs.libsu)
            implementation(libs.androidx.appcompat)
        }
        commonMain.dependencies {
            api(project(":parser"))
            implementation(libs.kotlinx.serialization.json)

            // Corutines
            implementation(libs.kotlinx.coroutines.core)

            // Logging
            implementation(libs.kermit)

            // Util
            implementation(libs.ipaddress)

        }
        jvmMain.dependencies {
            implementation(libs.logback.classic)
        }
    }
}

mavenPublishing {
    coordinates(group.toString(), "backend", version.toString())
    pom {
        name = "WG Tunnel Backend"
        description = "The core backend library for WG Tunnel apps."
        inceptionYear = "2026"
        url = "https://github.com/wgtunnel/core"
        licenses {
            license {
                name = "MIT License"
                url = "https://github.com/wgtunnel/core/blob/main/LICENSE"
                distribution = "repo"
            }
            license {
                name = "BSD 3-Clause License"
                url = "https://github.com/wgtunnel/core/blob/master/LICENSES/BSD-3-Clause.txt"
                distribution = "repo"
            }
        }
        developers {
            developer {
                id = "zaneschepke"
                name = "Zane Schepke"
                url = "https://zaneschepke.com"
                email = "dev@zaneschepke.com"
            }
        }
        scm {
            connection.set("scm:git:git://github.com/wgtunnel/core.git")
            developerConnection.set("scm:git:ssh://git@github.com/wgtunnel/core.git")
            url.set("https://github.com/wgtunnel/core")
        }
    }
}

val goDir = layout.projectDirectory.dir("native/backend")
val jvmNativeResources = layout.projectDirectory.dir("src/jvmMain/resources/natives")

val buildDesktopNatives = tasks.register<Exec>("buildDesktopNatives") {
    group = "build"
    description = "Build desktop JNI shared libraries into jvmMain/resources"
    workingDir = goDir.asFile

    inputs.files(
        fileTree(goDir.asFile) {
            include("**/*.go", "**/go.mod", "**/go.sum", "Makefile", "jni/**")
            exclude("out/**", "build/**", ".gocache/**")
        }
    ).withPathSensitivity(PathSensitivity.RELATIVE)

    outputs.dir(jvmNativeResources)

    val javaHome = providers.environmentVariable("JAVA_HOME")
        .orElse(providers.systemProperty("java.home"))
        .get()

    environment(
        "JAVA_HOME" to javaHome,
        "RESOURCEDIR" to jvmNativeResources.asFile.absolutePath,
        "DESTDIR" to goDir.dir("out").asFile.absolutePath,
    )

    commandLine("make", "desktop")
}

tasks.named("jvmProcessResources") { dependsOn(buildDesktopNatives) }
tasks.named("compileKotlinJvm") { dependsOn(buildDesktopNatives) }

val cleanDesktopNatives = tasks.register<Exec>("cleanDesktopNatives") {
    description = "Cleaning making"
    workingDir = goDir.asFile
    commandLine("make", "clean")
    isIgnoreExitValue = true
}

tasks.named<Delete>("clean") {
    dependsOn(cleanDesktopNatives)
    delete(goDir.dir("build"), goDir.dir("out"), jvmNativeResources)
}