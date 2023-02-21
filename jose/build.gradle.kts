import org.gradle.internal.os.OperatingSystem
import org.jetbrains.dokka.gradle.DokkaTask
import org.jetbrains.kotlin.gradle.targets.js.webpack.KotlinWebpackOutput.Target

version = rootProject.version
val currentModuleName = "ApolloJOSE"
val os: OperatingSystem = OperatingSystem.current()

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization") version "1.7.20"
    kotlin("native.cocoapods")
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
    if (os.isMacOsX) {
        ios()
//        tvos()
//        watchos()
//        macosX64()
//        if (System.getProperty("os.arch") != "x86_64") { // M1Chip
//            iosSimulatorArm64()
//            tvosSimulatorArm64()
//            watchosSimulatorArm64()
//            macosArm64()
//        }
    }
//    if (os.isWindows) {
//        // mingwX86() // it depend on kotlinx-datetime lib to support this platform before we can support it as well
//        mingwX64()
//    }
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

    if (os.isMacOsX) {
        cocoapods {
            this.summary = "ApolloJOSE is Json Object Signing & Encryption"
            this.version = rootProject.version.toString()
            this.authors = "IOG"
            this.ios.deploymentTarget = "13.0"
            this.osx.deploymentTarget = "12.0"
            this.tvos.deploymentTarget = "13.0"
            this.watchos.deploymentTarget = "8.0"
            framework {
                this.baseName = currentModuleName
            }
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(project(":utils"))
                implementation(project(":base64"))
                implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.4.0")
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.4.1")
                // implementation(project(":base-asymmetric-encryption"))
                // implementation(project(":hashing"))
            }
        }
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }
        val jvmMain by getting {
            dependencies {
                // implementation("org.bouncycastle:bcprov-jdk15on:1.68")
            }
        }
        val jvmTest by getting
        val androidMain by getting {
            dependencies {
                // implementation("org.bouncycastle:bcprov-jdk15on:1.68")
            }
        }
        val androidTest by getting {
            dependencies {
                implementation("junit:junit:4.13.2")
            }
        }
        val jsMain by getting {
            dependencies {
                // implementation(npm("elliptic", "6.5.4"))
                // implementation(npm("@types/elliptic", "6.4.14"))

                // Polyfill dependencies
                // implementation(npm("stream-browserify", "3.0.0"))
                // implementation(npm("buffer", "6.0.3"))

                // implementation("org.jetbrains.kotlin-wrappers:kotlin-web:1.0.0-pre.461")
                // implementation("org.jetbrains.kotlin-wrappers:kotlin-node:18.11.13-pre.461")
            }
        }
        val jsTest by getting
        if (os.isMacOsX) {
            val iosMain by getting
            val iosTest by getting
//            val tvosMain by getting
//            val tvosTest by getting
//            val watchosMain by getting
//            val watchosTest by getting
//            val macosX64Main by getting
//            val macosX64Test by getting
//            if (System.getProperty("os.arch") != "x86_64") { // M1Chip
//                val iosSimulatorArm64Main by getting {
//                    this.dependsOn(iosMain)
//                }
//                val iosSimulatorArm64Test by getting {
//                    this.dependsOn(iosTest)
//                }
//                val tvosSimulatorArm64Main by getting {
//                    this.dependsOn(tvosMain)
//                }
//                val tvosSimulatorArm64Test by getting {
//                    this.dependsOn(tvosTest)
//                }
//                val watchosSimulatorArm64Main by getting {
//                    this.dependsOn(watchosMain)
//                }
//                val watchosSimulatorArm64Test by getting {
//                    this.dependsOn(watchosTest)
//                }
//                val macosArm64Main by getting {
//                    this.dependsOn(macosX64Main)
//                }
//                val macosArm64Test by getting {
//                    this.dependsOn(macosX64Test)
//                }
//            }
        }
//        if (os.isWindows) {
//            // val mingwX86Main by getting // it depend on kotlinx-datetime lib to support this platform before we can support it as well
//            // val mingwX86Test by getting // it depend on kotlinx-datetime lib to support this platform before we can support it as well
//            val mingwX64Main by getting
//            val mingwX64Test by getting
//        }
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
        This is a Kotlin Multiplatform Library for JOSE
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

// TODO(Investigate why the below tasks fails)
tasks.matching {
    fun String.isOneOf(values: List<String>): Boolean {
        for (value in values) {
            if (this == value) {
                return true
            }
        }
        return false
    }

    it.name.isOneOf(
        listOf(
            "linkPodReleaseFrameworkIosFat",
            ":linkPodReleaseFrameworkIosFat",
            ":base-asymmetric-encryption:linkPodReleaseFrameworkIosFat",
            "linkPodDebugFrameworkIosFat",
            ":linkPodDebugFrameworkIosFat",
            ":base-asymmetric-encryption:linkPodDebugFrameworkIosFat"
        )
    )
}.all {
    this.enabled = false
}
