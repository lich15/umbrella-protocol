// Root Gradle build — только plugin declarations; реальная config в
// app/build.gradle.kts.
//
// Root Gradle build — only plugin declarations; real config in
// app/build.gradle.kts.

plugins {
    id("com.android.application") version "8.5.2" apply false
    kotlin("android") version "2.0.21" apply false
}
