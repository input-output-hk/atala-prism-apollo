import org.jetbrains.kotlin.gradle.targets.js.nodejs.NodeJsRootExtension
import org.jetbrains.kotlin.gradle.targets.js.nodejs.NodeJsRootPlugin

plugins {
    id("org.jetbrains.dokka") version "1.7.10"
    id("org.jlleitschuh.gradle.ktlint") version "11.0.0"
    id("maven-publish")
}

buildscript {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.7.21")
        classpath("com.android.tools.build:gradle:7.2.2")
    }
}

version = "1.0.0-alpha"
group = "io.iohk.atala.prism"

allprojects {
    group = "io.iohk.atala.prism"

    repositories {
        google()
        mavenCentral()
    }

    val listOfModulesNotToPublish = listOf(
        "utils",
        "base-symmetric-encryption",
        "base-asymmetric-encryption"
    )

    if (listOfModulesNotToPublish.contains(name).not()) {
        apply(plugin = "org.gradle.maven-publish")

        publishing {
            repositories {
                maven {
                    this.name = "GitHubPackages"
                    this.url = uri("https://maven.pkg.github.com/input-output-hk/atala-prism-apollo")
                    credentials {
                        this.username = getLocalProperty("username") ?: System.getenv("ATALA_GITHUB_ACTOR")
                        this.password = getLocalProperty("token") ?: System.getenv("ATALA_GITHUB_TOKEN")
                    }
                }
            }
        }
    }
}

subprojects {
    apply(plugin = "org.jlleitschuh.gradle.ktlint")

    configure<org.jlleitschuh.gradle.ktlint.KtlintExtension> {
        verbose.set(true)
        outputToConsole.set(true)
        filter {
            exclude("/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/**")
            exclude {
                it.file.toString().contains("external")
            }
        }
    }
}

rootProject.plugins.withType(NodeJsRootPlugin::class.java) {
    rootProject.extensions.getByType(NodeJsRootExtension::class.java).nodeVersion = "16.17.0"
}

tasks.dokkaGfmMultiModule.configure {
    outputDirectory.set(buildDir.resolve("dokkaCustomMultiModuleOutput"))
}

ktlint {
    filter {
        exclude(
            "/github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/**",
            "/github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/*",
            "/github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/bnjs.kt",
            "/github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/curve.kt",
            "/github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/curves.kt",
            "/github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/ellipticjs.kt",

            "github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/**",
            "github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/*",
            "github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/bnjs.kt",
            "github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/curve.kt",
            "github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/curves.kt",
            "github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/ellipticjs.kt",

            "./github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/**",
            "./github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/*",
            "./github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/bnjs.kt",
            "./github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/curve.kt",
            "./github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/curves.kt",
            "./github/workspace/base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/ellipticjs.kt"
        )
        exclude("./base-asymmetric-encryption/src/jsMain/kotlin/io/iohk/atala/prism/apollo/utils/external/**")
        exclude {
            it.file.toString().contains("external")
        }
        exclude { projectDir.toURI().relativize(it.file.toURI()).path.contains("/external/") }
    }
}

/**
 * Read any properties file and return the value of the key passed
 *
 * @param key value to key that needs reading
 * @param file file name in root folder that will be read with default value of "local.properties"
 * @throws [IllegalStateException] in case of failing to read file
 *
 * @return value of the key if found
 */
@kotlin.jvm.Throws(IllegalStateException::class)
fun Project.getLocalProperty(key: String, file: String = "local.properties"): String? {
    require(file.endsWith(".properties"))
    val properties = java.util.Properties()
    val localProperties = File(file)
    if (localProperties.isFile) {
        java.io.InputStreamReader(java.io.FileInputStream(localProperties), Charsets.UTF_8).use { reader ->
            properties.load(reader)
        }
    } else {
        // Handle CI in GitHub doesn't have `local.properties` file
        if (File(".").absolutePath.contains("github/workspace")) {
            return "null"
        } else {
            error("$file File not found. In path: ${File(".").absolutePath}")
        }
    }

    val value = properties.getProperty(key, "null")

    return if (value == "null") null else value
}
