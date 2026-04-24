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

// Top-level build file where you can add configuration options common to all sub-projects/modules.
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.spotless)
}

val ndkVersion = "28.2.13676358"

spotless {
    lineEndings = com.diffplug.spotless.LineEnding.UNIX

    java {
        target("**/src/*/java/**/*.java")
        targetExclude("**/api/**", "**/build/**")

        palantirJavaFormat()
        importOrder()
        removeUnusedImports()
        formatAnnotations()
    }

    kotlin {
        target("**/src/*/kotlin/**/*.kt", "**/src/*/java/**/*.kt")
        targetExclude("**/api/**", "**/build/**")
        ktlint().editorConfigOverride(
            mapOf(
                "standard:backing-property-naming" to "disabled",
                "standard:no-wildcard-imports" to "disabled",
                "standard:property-naming" to "disabled",
                "standard:function-naming" to "disabled",
                "standard:max-line-length" to "disabled",
                "standard:comment-wrapping" to "disabled"
            )
        )
    }

    format("cpp") {
        target("**/src/main/cpp/**/*.c", "**/src/main/cpp/**/*.cpp", "**/src/main/cpp/**/*.h", "**/src/main/cpp/**/*.hpp")
        targetExclude("**/api/**", "**/build/**")

        var sdkDir = ""
        val properties = Properties()
        val localProps = file("local.properties")
        if (localProps.exists()) {
            localProps.inputStream().use { properties.load(it) }
            sdkDir = properties.getProperty("sdk.dir") ?: ""
        }
        if (sdkDir.isBlank()) {
            sdkDir = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT") ?: ""
        }
        if (sdkDir.isBlank()) {
            val commonPaths = listOf("/opt/android-sdk", "/usr/local/lib/android/sdk")
            for (path in commonPaths) {
                if (file(path).exists()) {
                    sdkDir = path
                    break
                }
            }
        }

        val osName = System.getProperty("os.name").lowercase()
        val platform = when {
            osName.contains("linux") -> "linux-x86_64"
            osName.contains("mac") -> "darwin-x86_64"
            else -> "windows-x86_64"
        }
        var clangPath = "$sdkDir/ndk/$ndkVersion/toolchains/llvm/prebuilt/$platform/bin/clang-format"
        if (osName.contains("windows")) clangPath += ".exe"

        val clangFile = file(clangPath)
        if (clangFile.exists()) {
            clangFormat("19.0.1").style("file").pathToExe(clangPath)
        } else {
            println("Spotless Warning: Clang-format not found at $clangPath")
            clangFormat().style("file")
        }
    }
}

tasks.register("format") {
    dependsOn("spotlessApply")
    group = "formatting"
    description = "Formats the code using Spotless"
}
