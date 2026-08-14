/*
 * Copyright (C) 2026 XiaoTong6666
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.util.Properties
import io.github.xiaotong6666.fusehide.gradle.AdbModuleTask
import io.github.xiaotong6666.fusehide.gradle.ModuleInstallerMode

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.androidx.baselineprofile)
    id("kotlin-parcelize")
}

val localProperties = Properties()
val localPropertiesFile = rootProject.file("local.properties")
if (localPropertiesFile.exists()) {
    localPropertiesFile.inputStream().use { localProperties.load(it) }
}

val gitCommitId = rootProject.extra["gitCommitId"] as String
val gitCommitCount = rootProject.extra["gitCommitCount"] as Int
val fuseHideVersionName = "1.$gitCommitCount"

android {
    namespace = "io.github.xiaotong6666.fusehide"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.xiaotong6666.fusehide"
        minSdk = 31
        targetSdk = 37
        versionCode = gitCommitCount
        versionName = fuseHideVersionName

        buildConfigField("String", "COMMIT_HASH", "\"$gitCommitId\"")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++20", "-fvisibility=hidden")
            }
        }
    }

    signingConfigs {
        val keystorePath = localProperties.getProperty("ANDROID_DEBUG_KEYSTORE")
        val keystoreFile = listOfNotNull(
            keystorePath?.takeIf { it.isNotBlank() }?.let(::file),
            file(System.getProperty("user.home") + "/.android/debug.keystore"),
        ).firstOrNull { it.exists() }
        if (keystoreFile != null) {
            register("debugKey") {
                storeFile = keystoreFile
                storePassword = "android"
                keyAlias = "androiddebugkey"
                keyPassword = "android"
            }
        }
    }

    buildTypes {
        getByName("release") {
            signingConfigs.findByName("debugKey")?.let { signingConfig = it }
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        getByName("debug") {
            signingConfigs.findByName("debugKey")?.let { signingConfig = it }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
            freeCompilerArgs.addAll(
                "-opt-in=androidx.compose.material3.ExperimentalMaterial3Api",
                "-opt-in=androidx.compose.material3.ExperimentalMaterial3ExpressiveApi",
            )
        }
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    sourceSets {
        getByName("main") {
            java.directories.clear()
            java.directories.add("src/main/java/io/github/xiaotong6666/fusehide")
            kotlin.directories.clear()
            kotlin.directories.add("src/main/java/io/github/xiaotong6666/fusehide")
        }
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
}

dependencies {
    compileOnly(libs.api)
    implementation(project(path = ":uihelper"))
    implementation(libs.miuix.ui)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.navigationevent.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.viewmodel.navigation3)
    implementation(libs.androidx.navigation3.runtime)
    implementation(libs.material.kolor)
    implementation(libs.miuix.navigation3.ui)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    implementation(libs.androidx.profileinstaller)
    add("baselineProfile", project(path = ":baselineprofile"))
}

fun String.capitalized(): String = replaceFirstChar { char ->
    if (char.isLowerCase()) char.titlecase() else char.toString()
}

listOf("debug", "release").forEach { buildType ->
    val variant = buildType.capitalized()
    val buildMetadata = "$gitCommitCount-$gitCommitId-$buildType"
    val zipName = "FuseHide-${fuseHideVersionName}_${buildMetadata}.zip"
    val zipOutput = layout.buildDirectory.file("zygisk/$zipName")
    val zipTask = tasks.register<Exec>("zip$variant") {
        group = "build"
        description = "Builds the FuseHide $buildType Zygisk module ZIP"
        dependsOn("assemble$variant")
        workingDir(rootDir)
        commandLine(
            "python3",
            rootProject.file("scripts/repack-zygisk.py").absolutePath,
            "--build-type",
            buildType,
            "--skip-build",
        )
        inputs.file(rootProject.file("scripts/repack-zygisk.py"))
        inputs.dir(rootProject.file("template/module"))
        inputs.dir(layout.buildDirectory.dir("outputs/apk/$buildType"))
        outputs.file(zipOutput)
    }

    fun registerAdbTask(
        name: String,
        installerMode: ModuleInstallerMode? = null,
        shouldReboot: Boolean = false,
    ) {
        tasks.register<AdbModuleTask>(name) {
            dependsOn(zipTask)
            moduleZip.set(zipOutput)
            installerMode?.let { installer.set(it) }
            reboot.set(shouldReboot)
            device.convention(providers.gradleProperty("device"))
        }
    }

    registerAdbTask("push$variant")
    registerAdbTask("flash$variant", ModuleInstallerMode.AUTO)
    registerAdbTask("flashWithMagisk$variant", ModuleInstallerMode.MAGISK)
    registerAdbTask("flashWithKsud$variant", ModuleInstallerMode.KERNEL_SU)
    registerAdbTask("flashAndReboot$variant", ModuleInstallerMode.AUTO, shouldReboot = true)
    registerAdbTask(
        "flashWithMagiskAndReboot$variant",
        ModuleInstallerMode.MAGISK,
        shouldReboot = true,
    )
    registerAdbTask(
        "flashWithKsudAndReboot$variant",
        ModuleInstallerMode.KERNEL_SU,
        shouldReboot = true,
    )
}

tasks.register("packageZygiskModule") {
    group = "build"
    description = "Builds the debug FuseHide Zygisk module ZIP"
    dependsOn("zipDebug")
}
