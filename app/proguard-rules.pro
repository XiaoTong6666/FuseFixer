# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# libxposed API 101 entry points are referenced from META-INF/xposed/java_init.list
# and META-INF/xposed/native_init.list, so R8 must not rename or remove them in release builds.
-keep class io.github.xiaotong6666.fusehide.xposed.Entry { *; }
-keepnames class io.github.xiaotong6666.fusehide.xposed.Entry
-keep class * extends io.github.libxposed.api.XposedModule { *; }

# native_init is resolved via dlsym – symbol name must not be mangled
-keepclasseswithmembernames class * {
    native <methods>;
}

# These are reached from the module entry and receiver registration path.
-keep class io.github.xiaotong6666.fusehide.status.StatusBroadcastReceiver { *; }
-keep class io.github.xiaotong6666.fusehide.xposed.MainThreadTask { *; }

# Zygisk entry called via reflection; class and method names must be preserved.
-keep class io.github.xiaotong6666.fusehide.xposed.ZygiskEntry { *; }

# JNI methods are registered explicitly from the injected process. Keep every
# declaration, including methods that currently have no Java-side caller.
-keep class io.github.xiaotong6666.fusehide.config.HideConfigNativeBridge { *; }
-keepnames class io.github.xiaotong6666.fusehide.config.HideConfigNativeBridge
