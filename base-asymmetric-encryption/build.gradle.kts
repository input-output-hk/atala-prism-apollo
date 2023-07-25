import org.gradle.internal.os.OperatingSystem
import org.jetbrains.dokka.gradle.DokkaTask
import org.jetbrains.kotlin.gradle.targets.js.webpack.KotlinWebpackOutput.Target

val currentModuleName = "ApolloBaseAsymmetricEncryption"
val os: OperatingSystem = OperatingSystem.current()

plugins {
    kotlin("multiplatform")
    id("com.chromaticnoise.multiplatform-swiftpackage") version "2.0.3"
    id("com.android.library")
    id("org.jetbrains.dokka")
}

kotlin {
    android {
        publishAllLibraryVariants()
    }

    jvm {
        compilations.all {
            kotlinOptions {
                jvmTarget = "11"
            }
        }

        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
    }
    ios()
    macosX64()

    if (System.getProperty("os.arch") != "x86_64") { // M1Chip
        iosSimulatorArm64()
//            tvosSimulatorArm64()
//            watchosSimulatorArm64()
        macosArm64()
    }
    js(IR) {
        this.moduleName = currentModuleName
        this.binaries.library()
        this.useCommonJs()
        this.compilations["main"].packageJson {
            this.version = rootProject.version.toString()
        }
        this.compilations["test"].packageJson {
            this.version = rootProject.version.toString()
        }
        browser {
            this.webpackTask {
                this.output.library = currentModuleName
                this.output.libraryTarget = Target.VAR
            }
            this.commonWebpackConfig {
                this.cssSupport {
                    this.enabled = true
                }
            }
            this.testTask {
                if (os.isWindows) {
                    this.enabled = false
                }
                this.useKarma {
                    this.useChromeHeadless()
                }
            }
        }
        nodejs {
            this.testTask {
                if (os.isWindows) {
                    this.enabled = false
                }
                this.useKarma {
                    this.useChromeHeadless()
                }
            }
        }
    }

    multiplatformSwiftPackage {
        packageName("Apollo")
        swiftToolsVersion("5.3")
        targetPlatforms {
            iOS { v("13") }
            macOS { v("11") }
        }
        outputDirectory(File(rootDir, "base-asymmetric-encryption/build/packages/ApolloSwift"))
    }

//    if (os.isMacOsX) {
//        cocoapods {
//            this.summary = "ApolloBaseAsymmetricEncryption is a base for symmetric encryption libs"
//            this.version = rootProject.version.toString()
//            this.authors = "IOG"
//            this.ios.deploymentTarget = "13.0"
//            this.osx.deploymentTarget = "12.0"
//            this.tvos.deploymentTarget = "13.0"
//            this.watchos.deploymentTarget = "8.0"
//            framework {
//                this.baseName = currentModuleName
//                isStatic = false
//                transitiveExport = false
//                embedBitcode("disable")
//            }
//
//            pod("IOHKRSA") {
//                version = "1.0.0"
//                source = path(project.file("../iOSLibs/IOHKRSA"))
//            }
//
//            pod("IOHKSecureRandomGeneration") {
//                version = "1.0.0"
//                packageName = "IOHKSecureRandomGeneration1"
//                source = path(project.file("../iOSLibs/IOHKSecureRandomGeneration"))
//            }
//
//            pod("IOHKCryptoKit") {
//                version = "1.0.0"
//                source = path(project.file("../iOSLibs/IOHKCryptoKit"))
//            }
//        }
//    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(project(":utils"))
                implementation(project(":secure-random"))
                implementation(project(":hashing"))
                implementation("com.ionspin.kotlin:bignum:0.3.7")
                implementation(project(":base64"))
                implementation("org.kotlincrypto.macs:hmac-sha2:0.3.0")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(project(":base64"))
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.4") // or the latest version
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.6.4")
            }
        }
        val jvmMain by getting {
            dependencies {
                dependencies {
                    api("fr.acinq.secp256k1:secp256k1-kmp:0.9.0")
                }
                val target = when {
                    os.isLinux -> "linux"
                    os.isMacOsX -> "darwin"
                    os.isWindows -> "mingw"
                    else -> error("Unsupported OS $os")
                }
                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm-$target:0.9.0")
                implementation("com.google.guava:guava:30.1-jre")
                implementation("org.bouncycastle:bcprov-jdk15on:1.68")
            }
        }
        val jvmTest by getting
        val androidMain by getting {
            dependencies {
                api("fr.acinq.secp256k1:secp256k1-kmp:0.9.0")
                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.9.0")
                implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-android:0.9.0")
                implementation("com.google.guava:guava:30.1-jre")
                implementation("org.bouncycastle:bcprov-jdk15on:1.68")
            }
        }
        val androidTest by getting {
            dependencies {
                implementation("junit:junit:4.13.2")
            }
        }
        val jsMain by getting {
            dependencies {
                implementation(project(":base64"))

                implementation(npm("elliptic", "6.5.4"))
                implementation(npm("@types/elliptic", "6.4.14"))
                implementation(npm("@noble/secp256k1", "2.0.0"))
                implementation(npm("@stablelib/x25519", "1.0.3"))

                // Polyfill dependencies
                implementation(npm("stream-browserify", "3.0.0"))
                implementation(npm("buffer", "6.0.3"))

                implementation("org.jetbrains.kotlin-wrappers:kotlin-web:1.0.0-pre.461")
                implementation("org.jetbrains.kotlin-wrappers:kotlin-node:18.11.13-pre.461")
            }
        }
        val jsTest by getting

        val iosMain by getting {
            dependencies {
                implementation(project(":secp256k1-kmp"))
                implementation(project(":iOSLibs"))
            }
        }

        val iosTest by getting {
            this.dependsOn(commonTest)
        }
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
//        if (os.isWindows) {
//            // val mingwX86Main by getting // it depend on kotlinx-datetime lib to support this platform before we can support it as well
//            // val mingwX86Test by getting // it depend on kotlinx-datetime lib to support this platform before we can support it as well
//            val mingwX64Main by getting
//            val mingwX64Test by getting
//        }
    }

    if (os.isMacOsX) {
        tasks.getByName<org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest>("iosX64Test") {
            deviceId = "iPhone 14 Plus"
        }
        if (System.getProperty("os.arch") != "x86_64") { // M1Chip
            tasks.getByName<org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest>("iosSimulatorArm64Test") {
                deviceId = "iPhone 14 Plus"
            }
        }
    }
}

android {
    compileSdk = 32
    sourceSets["main"].manifest.srcFile("src/androidMain/AndroidManifest.xml")
    defaultConfig {
        minSdk = 21
        targetSdk = 32
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    /**
     * Because Software Components will not be created automatically for Maven publishing from
     * Android Gradle Plugin 8.0. To opt-in to the future behavior, set the Gradle property android.
     * disableAutomaticComponentCreation=true in the `gradle.properties` file or use the new
     * publishing DSL.
     */
    publishing {
        multipleVariants {
            withSourcesJar()
            withJavadocJar()
            allVariants()
        }
    }
}

// Dokka implementation
tasks.withType<DokkaTask> {
    moduleName.set(project.name)
    moduleVersion.set(rootProject.version.toString())
    description = """
        This is a Kotlin Multiplatform Library for Base Asymmetric Encryption
    """.trimIndent()
    dokkaSourceSets {
        // TODO: Figure out how to include files to the documentations
        named("commonMain") {
            includes.from("Module.md", "docs/Module.md")
        }
    }
}

// afterEvaluate {
//    tasks.withType<AbstractTestTask> {
//        testLogging {
//            events("passed", "skipped", "failed", "standard_out", "standard_error")
//            showExceptions = true
//            showStackTraces = true
//        }
//    }
// }

ktlint {
    filter {
        exclude("**/external/*", "./src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/*")
        exclude {
            it.file.toString().contains("external")
        }
        exclude { projectDir.toURI().relativize(it.file.toURI()).path.contains("/external/") }
    }
}

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
