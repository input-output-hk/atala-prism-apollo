pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

rootProject.name = "apollo"
include(":Apollo")
include(":Hashing")
include(":UUID")
include(":Base64")
include(":JWT")
