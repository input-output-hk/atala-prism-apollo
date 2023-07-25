import org.gradle.internal.os.OperatingSystem

val currentModuleName = "ApolloIOSLibs"
val os: OperatingSystem = OperatingSystem.current()

plugins {
    kotlin("multiplatform")
    kotlin("native.cocoapods")
}

kotlin {
    ios()
    macosX64()

    if (System.getProperty("os.arch") != "x86_64") { // M1Chip
        iosSimulatorArm64()
//            tvosSimulatorArm64()
//            watchosSimulatorArm64()
        macosArm64()
    }

    if (os.isMacOsX) {
        cocoapods {
            this.summary = "ApolloBaseAsymmetricEncryption is a base for symmetric encryption libs"
            this.version = rootProject.version.toString()
            this.authors = "IOG"
            this.ios.deploymentTarget = "13.0"
            this.osx.deploymentTarget = "12.0"
            this.tvos.deploymentTarget = "13.0"
            this.watchos.deploymentTarget = "8.0"
            framework {
                this.baseName = currentModuleName
                isStatic = false
                embedBitcode("disable")
            }

            pod("IOHKRSA") {
                version = "1.0.0"
                source = path(project.file("../iOSLibs/IOHKRSA"))
            }

            pod("IOHKSecureRandomGeneration") {
                version = "1.0.0"
                packageName = "IOHKSecureRandomGeneration1"
                source = path(project.file("../iOSLibs/IOHKSecureRandomGeneration"))
            }

            pod("IOHKCryptoKit") {
                version = "1.0.0"
                source = path(project.file("../iOSLibs/IOHKCryptoKit"))
            }
        }
    }

    sourceSets {
//        val commonMain by getting {
//            dependencies {
//                implementation(project(":utils"))
//                implementation(project(":secure-random"))
//                implementation(project(":hashing"))
//                implementation("com.ionspin.kotlin:bignum:0.3.7")
//                implementation(project(":base64"))
//                implementation("org.kotlincrypto.macs:hmac-sha2:0.3.0")
//            }
//        }
//        val commonTest by getting {
//            dependencies {
//                implementation(kotlin("test"))
//                implementation(project(":base64"))
//                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.4") // or the latest version
//                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.6.4")
//            }
//        }
//        val jvmMain by getting {
//            dependencies {
//                dependencies {
//                    api("fr.acinq.secp256k1:secp256k1-kmp:0.9.0")
//                }
//                val target = when {
//                    os.isLinux -> "linux"
//                    os.isMacOsX -> "darwin"
//                    os.isWindows -> "mingw"
//                    else -> error("Unsupported OS $os")
//                }
//                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-$target:0.9.0")
//                implementation("com.google.guava:guava:30.1-jre")
//                implementation("org.bouncycastle:bcprov-jdk15on:1.68")
//            }
//        }
//        val jvmTest by getting
//        val androidMain by getting {
//            dependencies {
//                api("fr.acinq.secp256k1:secp256k1-kmp:0.9.0")
//                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.9.0")
//                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-android:0.9.0")
//                implementation("com.google.guava:guava:30.1-jre")
//                implementation("org.bouncycastle:bcprov-jdk15on:1.68")
//            }
//        }
//        val androidTest by getting {
//            dependencies {
//                implementation("junit:junit:4.13.2")
//            }
//        }
//        val jsMain by getting {
//            dependencies {
//                implementation(project(":base64"))
//
//                implementation(npm("elliptic", "6.5.4"))
//                implementation(npm("@types/elliptic", "6.4.14"))
//                implementation(npm("@noble/secp256k1", "2.0.0"))
//                implementation(npm("@stablelib/x25519", "1.0.3"))
//
//                // Polyfill dependencies
//                implementation(npm("stream-browserify", "3.0.0"))
//                implementation(npm("buffer", "6.0.3"))
//
//                implementation("org.jetbrains.kotlin-wrappers:kotlin-web:1.0.0-pre.461")
//                implementation("org.jetbrains.kotlin-wrappers:kotlin-node:18.11.13-pre.461")
//            }
//        }
//        val jsTest by getting

        val iosMain by getting {
            dependencies {
                implementation(project(":utils"))
            }
        }
        val iosTest by getting
        val macosX64Main by getting {
            this.dependsOn(iosMain)
        }
        val macosX64Test by getting {
            this.dependsOn(iosTest)
        }
        if (System.getProperty("os.arch") != "x86_64") { // M1Chip
            val iosSimulatorArm64Main by getting {
                this.dependsOn(iosMain)
            }
            val iosSimulatorArm64Test by getting {
                this.dependsOn(iosTest)
            }
            val macosArm64Main by getting { this.dependsOn(macosX64Main) }
            val macosArm64Test by getting { this.dependsOn(macosX64Test) }
        }
    }
}

// Dokka implementation
// tasks.withType<DokkaTask> {
//    moduleName.set(project.name)
//    moduleVersion.set(rootProject.version.toString())
//    description = """
//        This is a Kotlin Multiplatform Library for Base Asymmetric Encryption
//    """.trimIndent()
//    dokkaSourceSets {
//        // TODO: Figure out how to include files to the documentations
//        named("commonMain") {
//            includes.from("Module.md", "docs/Module.md")
//        }
//    }
// }

// afterEvaluate {
//    tasks.withType<AbstractTestTask> {
//        testLogging {
//            events("passed", "skipped", "failed", "standard_out", "standard_error")
//            showExceptions = true
//            showStackTraces = true
//        }
//    }
// }

// ktlint {
//    filter {
//        exclude("**/external/*", "./src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/*")
//        exclude {
//            it.file.toString().contains("external")
//        }
//        exclude { projectDir.toURI().relativize(it.file.toURI()).path.contains("/external/") }
//    }
// }

// TODO(Investigate why the below tasks fails)
// tasks.matching {
//    fun String.isOneOf(values: List<String>): Boolean {
//        for (value in values) {
//            if (this == value) {
//                return true
//            }
//        }
//        return false
//    }
//
//    it.name.isOneOf(
//        listOf(
//            "linkPodReleaseFrameworkIosFat",
//            ":linkPodReleaseFrameworkIosFat",
//            ":base-asymmetric-encryption:linkPodReleaseFrameworkIosFat",
//            "linkPodDebugFrameworkIosFat",
//            ":linkPodDebugFrameworkIosFat",
//            ":base-asymmetric-encryption:linkPodDebugFrameworkIosFat"
//        )
//    )
// }.all {
//    this.enabled = false
// }
