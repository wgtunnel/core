plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.vanniktech.mavenPublish)
    signing
}

android {
    namespace = "com.wgtunnel.backend.android.jni"
    compileSdk {
        version = release(libs.versions.android.compileSdk.get().toInt())
    }

    ndkVersion = libs.versions.android.ndk.get()

    defaultConfig {
        ndk {
            abiFilters += listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
        }
        minSdk = libs.versions.android.minSdk.get().toInt()

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    externalNativeBuild {
        cmake {
            path = file("../backend/native/android/CMakeLists.txt")
        }
    }

    val basePackageName = namespace

    buildTypes {
        all {
            externalNativeBuild {
                cmake {
                    targets("libam-go.so", "libam.so", "libam-quick.so")
                    arguments("-DGRADLE_USER_HOME=${project.gradle.gradleUserHomeDir}")
                    arguments("-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON")
                }
            }
        }

        release {
            externalNativeBuild {
                cmake {
                    arguments("-DANDROID_PACKAGE_NAME=$basePackageName")
                }
            }
        }

        debug {
            externalNativeBuild {
                cmake {
                    arguments("-DANDROID_PACKAGE_NAME=$basePackageName.debug")
                }
            }
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

tasks.named<Delete>("clean") {
    delete(layout.projectDirectory.dir("src/main/jniLibs"))
    delete(layout.projectDirectory.dir(".cxx"))
}



