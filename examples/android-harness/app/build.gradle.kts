// Android app module для UmbrellaX test harness. Потребляет:
//  - libumbrella_ffi_kotlin.so per ABI из target/jniLibs/ (собирает build-aar.sh)
//  - Kotlin bindings copied into app/build/generated/source/uniffi/
//
// Android app module for UmbrellaX test harness. Consumes:
//  - libumbrella_ffi_kotlin.so per ABI from target/jniLibs/ (built by
//    build-aar.sh)
//  - Kotlin bindings copied into app/build/generated/source/uniffi/

plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "xyz.umbrellax.testharness"
    compileSdk = 35

    defaultConfig {
        applicationId = "xyz.umbrellax.testharness"
        // API 23 minimum: AndroidKeyStore доступен с 23; StrongBox — с 28
        // (fallback to TEE на 23-27).
        // API 23 minimum: AndroidKeyStore since 23; StrongBox since 28
        // (falls back to TEE on 23-27).
        minSdk = 23
        targetSdk = 35
        versionCode = 1
        versionName = "0.0.1"
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets {
        getByName("main") {
            java {
                // Keep generated UniFFI sources visible to IDE importers.
                srcDir("build/generated/source/uniffi")
            }
            jniLibs {
                // Native libs per ABI собранные build-aar.sh.
                // Per-ABI native libs built by build-aar.sh.
                srcDir("../../../target/jniLibs")
            }
        }
    }
}

kotlin {
    sourceSets {
        getByName("main") {
            kotlin.srcDir("build/generated/source/uniffi")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")

    // uniffi Kotlin runtime — JNA для native binding + coroutines для async.
    // uniffi Kotlin runtime — JNA for native binding + coroutines for async.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // EncryptedSharedPreferences для Identity seed storage (API 23+).
    // EncryptedSharedPreferences for identity-seed storage (API 23+).
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // Google Play Integrity API — AttestationBridge.
    // Google Play Integrity API — AttestationBridge.
    implementation("com.google.android.play:integrity:1.4.0")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.6.1")
}
