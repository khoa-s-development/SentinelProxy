@file:Suppress("UnstableApiUsage")

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        mavenCentral()
        maven("https://repo.papermc.io/repository/maven-public/")
    }
}

pluginManagement {
    includeBuild("build-logic")
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.9.0"
}

rootProject.name = "sentinalsProxy"

sequenceOf(
    "api",
    "native",
    "proxy",
).forEach {
    val project = ":sentinals-$it"
    include(project)
    project(project).projectDir = file(it)
}

// Include Configurate 3
val deprecatedConfigurateModule = ":deprecated-configurate3"
include(deprecatedConfigurateModule)
project(deprecatedConfigurateModule).projectDir = file("proxy/deprecated/configurate3")

// Log4J2 plugin
val log4j2ProxyPlugin = ":sentinals-proxy-log4j2-plugin"
include(log4j2ProxyPlugin)
project(log4j2ProxyPlugin).projectDir = file("proxy/log4j2-plugin")
