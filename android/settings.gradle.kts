pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}
// The QRST library (sign-in by a scanned code): the qr-secret-transfer repo, checked out beside this one.
includeBuild("../../qr-secret-transfer/kotlin")
rootProject.name = "keykin-android"
include(":app")
