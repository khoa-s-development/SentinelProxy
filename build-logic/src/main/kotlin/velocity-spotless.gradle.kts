import com.diffplug.gradle.spotless.SpotlessExtension

plugins {
    id("com.diffplug.spotless")
}

spotless {
    java {
        if (project.name == "velocity-api") {
            licenseHeaderFile(file("HEADER.txt"))
            targetExclude("**/java/com/velocitypowered/api/util/Ordered.java")
        } else {
            licenseHeaderFile(rootProject.file("HEADER.txt"))
        }
        removeUnusedImports()
    }
}
