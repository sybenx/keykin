plugins { kotlin("jvm") version "2.0.21" }

kotlin { jvmToolchain(17) }
sourceSets {
    main { kotlin.srcDir("../kotlin") }
    test { kotlin.srcDir("src") }
}
dependencies { testImplementation("junit:junit:4.13.2") }
tasks.test {
    systemProperty("calendar.vectors", file("../vectors/calendar.json").absolutePath)
    testLogging { events("passed", "failed"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
}
