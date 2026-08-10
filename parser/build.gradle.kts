plugins {
    kotlin("jvm")
    alias(libs.plugins.kotlinxSerialization)
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
