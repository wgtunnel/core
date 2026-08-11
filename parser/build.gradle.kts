plugins {
    kotlin("jvm")
    alias(libs.plugins.kotlinxSerialization)
    alias(libs.plugins.vanniktech.mavenPublish)
    signing
}

dependencies {
    testImplementation(kotlin("test"))

    implementation(libs.kotlinx.serialization.core)

    implementation(libs.crypto.rand)
    implementation(libs.bouncycastle)

    implementation(libs.human.readable)
    implementation(libs.kotlinx.datetime)
    implementation(libs.commons.validator)
}

tasks.test { useJUnitPlatform() }

signing {
    val inMemoryKey = providers.gradleProperty("signing.inMemoryKey")
    val password = providers.gradleProperty("signing.password")
    if (inMemoryKey.isPresent) {
        useInMemoryPgpKeys(inMemoryKey.get(), password.orNull.orEmpty())
    }
}

mavenPublishing {
    publishToMavenCentral()
    signAllPublications()
    coordinates(group.toString(), "parser", version.toString())
    pom {
        name = "WG Tunnel Parser"
        description = "WireGuard / Amnezia config parser for WG Tunnel."
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