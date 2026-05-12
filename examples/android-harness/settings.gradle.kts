// Gradle settings для UmbrellaX Android test harness.
// Минимальный single-module Gradle project, потребляющий
// libumbrella_ffi_kotlin.so + сгенерированные Kotlin bindings, copied into
// app/build/generated/source/uniffi/.
//
// Gradle settings for UmbrellaX Android test harness. A minimal
// single-module project consuming libumbrella_ffi_kotlin.so + generated
// Kotlin bindings copied into app/build/generated/source/uniffi/.

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "umbrella-android-harness"
include(":app")
