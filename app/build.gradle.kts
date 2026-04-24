plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "io.github.xiaotong6666.fusehide"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.xiaotong6666.fusehide"
        minSdk = 31
        targetSdk = 37
        
        val gitCommitCount = try {
            ProcessBuilder("git", "rev-list", "--count", "HEAD")
                .directory(rootDir)
                .start()
                .inputStream.bufferedReader().use { it.readText() }.trim().toInt()
        } catch (e: Exception) {
            1
        }
        
        versionCode = gitCommitCount
        versionName = "1.$gitCommitCount"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++20", "-fvisibility=hidden")
            }
        }
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    signingConfigs {
        val keystoreFile = file(System.getProperty("user.home") + "/.android/debug.keystore")
        if (keystoreFile.exists()) {
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
            val debugKey = signingConfigs.findByName("debugKey")
            if (debugKey != null) {
                signingConfig = debugKey
            }
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        getByName("debug") {
            val debugKey = signingConfigs.findByName("debugKey")
            if (debugKey != null) {
                signingConfig = debugKey
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
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
    compileOnly(project(":xposed-stubs"))
    implementation(libs.miuix)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}
