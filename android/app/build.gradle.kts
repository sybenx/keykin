// Keykin for Android. The FROST library comes from ../../frost, built for Android with
//   cargo ndk -t arm64-v8a -t x86_64 -P 30 -o app/src/main/jniLibs build --release --features jni
// and for this computer's unit tests with `cargo build --release --features jni`.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}
android {
    namespace = "cc.aaro.keykin"
    compileSdk = 35
    defaultConfig {
        applicationId = "cc.aaro.keykin"
        minSdk = 30; targetSdk = 35
        versionCode = 1; versionName = "0.1.0"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }
    buildTypes { release { isMinifyEnabled = false } }
    buildFeatures { compose = true; buildConfig = true }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    testOptions { unitTests.isReturnDefaultValues = true }
}
tasks.withType<Test>().configureEach {
    // The unit tests talk to a real box (KEYKIN_BOX_QR) with the FROST library built for this computer.
    systemProperty("keykin.frostlib", file("../../frost/target/release/libkeykin_frost.dylib").absolutePath)
    environment("KEYKIN_BOX_QR", System.getenv("KEYKIN_BOX_QR") ?: "")
    outputs.upToDateWhen { false }
    testLogging { events("passed", "failed", "skipped"); showStandardStreams = true; exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
}
dependencies {
    implementation("fr.acinq.secp256k1:secp256k1-kmp-jni-android:0.19.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment-ktx:1.8.5")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.ui:ui")
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
    testImplementation("fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.19.0")
}
