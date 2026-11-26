// Runs calendar/vectors/calendar.json against calendar/kotlin/Calendar.kt on the JVM. Not copied into apps.
//   ../../android/gradlew -p . test        (from calendar/test-kotlin; Java 17)
pluginManagement { repositories { mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositories { mavenCentral() } }
rootProject.name = "calendar-test"
