import org.jetbrains.kotlin.gradle.targets.js.nodejs.NodeJsRootExtension
import org.jetbrains.kotlin.gradle.targets.js.nodejs.NodeJsRootPlugin
import java.util.Base64

val publishedMavenId: String = "io.iohk.atala.prism.apollo"

plugins {
    id("org.jetbrains.dokka") version "1.9.10"
    id("org.jlleitschuh.gradle.ktlint") version "11.6.1"
    id("maven-publish")
    id("org.jetbrains.kotlinx.kover") version "0.7.4"
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0-rc-1"
    id("signing")
}

buildscript {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
    dependencies {
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.21")
        classpath("com.android.tools.build:gradle:7.2.2")
        classpath("org.jetbrains.dokka:dokka-base:1.9.10")
    }
}

group = publishedMavenId

dependencies {
    kover(project(":apollo"))
    kover(project("secp256k1-kmp"))
    kover(project("secp256k1-kmp:native"))
}

allprojects {
    group = publishedMavenId

    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }

    apply(plugin = "org.gradle.maven-publish")
    apply(plugin = "org.gradle.signing")

    // Allowed projects to publish to maven
    val allowedProjectsToPublish = listOf("apollo")
    if (allowedProjectsToPublish.contains(project.name)) {
        publishing {
            publications {
                withType<MavenPublication> {
                    groupId = publishedMavenId
                    artifactId = project.name
                    version = project.version.toString()
                    pom {
                        name.set("Atala PRISM Apollo")
                        description.set("Collection of the cryptographic methods used all around Atala PRISM")
                        url.set("https://docs.atalaprism.io/")
                        organization {
                            name.set("IOG")
                            url.set("https://iog.io/")
                        }
                        issueManagement {
                            system.set("Github")
                            url.set("https://github.com/input-output-hk/atala-prism-apollo")
                        }
                        licenses {
                            license {
                                name.set("The Apache License, Version 2.0")
                                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                            }
                        }
                        developers {
                            developer {
                                id.set("hamada147")
                                name.set("Ahmed Moussa")
                                email.set("ahmed.moussa@iohk.io")
                                organization.set("IOG")
                                roles.add("developer")
                            }
                            developer {
                                id.set("amagyar-iohk")
                                name.set("Allain Magyar")
                                email.set("allain.magyar@iohk.io")
                                organization.set("IOG")
                                roles.add("qc")
                            }
                            developer {
                                id.set("antonbaliasnikov")
                                name.set("Anton Baliasnikov")
                                email.set("anton.baliasnikov@iohk.io")
                                organization.set("IOG")
                                roles.add("qc")
                            }
                            developer {
                                id.set("elribonazo")
                                name.set("Javier Ribó")
                                email.set("javier.ribo@iohk.io")
                                organization.set("IOG")
                                roles.add("developer")
                            }
                            developer {
                                id.set("goncalo-frade-iohk")
                                name.set("Gonçalo Frade")
                                email.set("goncalo.frade@iohk.io")
                                organization.set("IOG")
                                roles.add("developer")
                            }
                            developer {
                                id.set("curtis-h")
                                name.set("Curtis Harding")
                                email.set("curtis.harding@iohk.io")
                                organization.set("IOG")
                                roles.add("developer")
                            }
                            developer {
                                id.set("cristianIOHK")
                                name.set("Cristian Gonzalez")
                                email.set("cristian.castro@iohk.io")
                                organization.set("IOG")
                                roles.add("developer")
                            }
                        }
                        scm {
                            connection.set("scm:git:git://input-output-hk/atala-prism-apollo.git")
                            developerConnection.set("scm:git:ssh://input-output-hk/atala-prism-apollo.git")
                            url.set("https://github.com/input-output-hk/atala-prism-apollo")
                        }
                    }
                    signing {
                        val base64EncodedAsciiArmoredSigningKey: String = System.getenv("BASE64_ARMORED_GPG_SIGNING_KEY_MAVEN") ?: ""
                        val signingKeyPassword: String = System.getenv("SIGNING_KEY_PASSWORD") ?: ""
                        useInMemoryPgpKeys(String(Base64.getDecoder().decode(base64EncodedAsciiArmoredSigningKey.toByteArray())), signingKeyPassword)
                        sign(this@withType)
                    }
                }
            }
            repositories {
                // GitHub Maven Repo
//            maven {
//                this.name = "GitHubPackages"
//                this.url = uri("https://maven.pkg.github.com/input-output-hk/atala-prism-apollo")
//                credentials {
//                    this.username = System.getenv("ATALA_GITHUB_ACTOR")
//                    this.password = System.getenv("ATALA_GITHUB_TOKEN")
//                }
//            }
            }
        }
    }
}

subprojects {
    apply(plugin = "org.jlleitschuh.gradle.ktlint")
    apply(plugin = "org.jetbrains.kotlinx.kover")

    koverReport {
        filters {
            excludes {
                classes(
                    "io.iohk.atala.prism.apollo.utils.bip39.wordlists.*"
                )
            }
        }
    }

    ktlint {
        verbose.set(true)
        outputToConsole.set(true)
        filter {
            exclude {
                it.file.toString().contains("external")
            }
            exclude {
                it.file.toString() == "BNjs.kt" || it.file.toString() == "Curve.kt" || it.file.toString() == "PresetCurve.kt" ||
                    it.file.toString() == "Ellipticjs.kt" || it.file.toString() == "secp256k1js.kt"
            }
            exclude {
                it.file.toString().contains("external")
            }
            exclude { projectDir.toURI().relativize(it.file.toURI()).path.contains("/external/") }
        }
    }
}

rootProject.plugins.withType(NodeJsRootPlugin::class.java) {
    rootProject.extensions.getByType(NodeJsRootExtension::class.java).nodeVersion = "16.17.0"
}

nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(uri("https://oss.sonatype.org/content/repositories/snapshots/"))
            username.set(System.getenv("SONATYPE_USERNAME"))
            password.set(System.getenv("SONATYPE_PASSWORD"))
        }
    }
}
