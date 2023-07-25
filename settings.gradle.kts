pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        google()
    }
}

buildscript {
    repositories {
        gradlePluginPortal()
        mavenCentral()
        mavenLocal()
        google()
        maven("https://plugins.gradle.org/m2/")
        // Needed for Kotlin coroutines that support new memory management mode
        maven {
            url = uri("https://maven.pkg.jetbrains.space/public/p/kotlinx-coroutines/maven")
        }
    }

    dependencies {
        classpath("io.arrow-kt:arrow-ank-gradle:0.11.0")
    }
}

rootProject.name = "apollo"
include(":apollo")
include(":hashing")
include(":uuid")
include(":base16")
include(":base32")
include(":base58")
include(":base64")
include(":multibase")
include(":utils")
include(":base-symmetric-encryption")
include(":secure-random")
include(":aes")
include(":base-asymmetric-encryption")
include(":iOSLibs")
// include(":rsa")
// include(":ecdsa")
include(":varint")
// include(":jose")
include("secp256k1-kmp")
include("secp256k1-kmp:native")
