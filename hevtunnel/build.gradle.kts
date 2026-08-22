plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.vanniktech.mavenPublish)
    signing
}

android {
    namespace = "com.wgtunnel.hevtunnel"

    compileSdk {
        version = release(libs.versions.android.compileSdk.get().toInt())
    }

    ndkVersion = libs.versions.android.ndk.get()

    defaultConfig {
        minSdk = libs.versions.android.minSdk.get().toInt()

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")

        ndk {
            abiFilters += listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
        }

        externalNativeBuild {
            ndkBuild {
                arguments.add("APP_CFLAGS+=-DPKGNAME=com/wgtunnel/hevtunnel -ffile-prefix-map=${rootDir}=.")
                arguments.add("APP_LDFLAGS+=-Wl,--build-id=none")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    externalNativeBuild {
        ndkBuild {
            path = file("src/main/jni/Android.mk")
        }
    }
}

signing {
    val inMemoryKey =
        providers
            .gradleProperty("signingInMemoryKey")
            .orElse(providers.gradleProperty("signing.inMemoryKey"))
    val password =
        providers
            .gradleProperty("signingInMemoryKeyPassword")
            .orElse(providers.gradleProperty("signing.password"))
    if (inMemoryKey.isPresent) {
        useInMemoryPgpKeys(inMemoryKey.get(), password.orNull.orEmpty())
    }
}
mavenPublishing {
    publishToMavenCentral()
    signAllPublications()
    coordinates(group.toString(), "hevtunnel", version.toString())
    pom {
        name = "hev-socks5-tunnel"
        description = "hev-socks5-tunnel JNI bindings for WG Tunnel."
        inceptionYear = "2026"
        url = "https://github.com/wgtunnel/core"
        licenses {
            license {
                name = "MIT License"
                url = "https://github.com/wgtunnel/core/blob/master/LICENSE"
                distribution = "repo"
            }
        }
        developers {
            developer {
                id = "zaneschepke"
                name = "Zane Schepke"
                url = "https://github.com/zaneschepke"
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