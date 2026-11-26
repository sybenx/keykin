plugins {
    id("com.android.application") version "8.7.1"
    id("org.jetbrains.kotlin.android") version "2.0.21"
}

android {
    namespace = "cc.aaro.calendar.test"
    compileSdk = 35
    defaultConfig {
        applicationId = "cc.aaro.calendar.test"
        minSdk = 26; targetSdk = 35
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    sourceSets["main"].java.srcDirs("../kotlin", "../android")
}

dependencies {
    androidTestImplementation("androidx.test:runner:1.5.2")
    androidTestImplementation("androidx.test:rules:1.5.0")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
}
