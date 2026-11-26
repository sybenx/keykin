// Runs calendar/android/AndroidCalendar.kt against a real calendar provider on an emulator. Not copied into apps.
//   ../../android/gradlew -p . connectedDebugAndroidTest      (from calendar/test-android; Java 17, one emulator up)
pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "calendar-test-android"
