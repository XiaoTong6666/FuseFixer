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

# LSPosed/Xposed entry points are referenced from assets/xposed_init and runtime callbacks,
# so R8 must not rename or remove them in release builds.
-keep class io.github.xiaotong6666.fusehide.Entry { *; }
-keepnames class io.github.xiaotong6666.fusehide.Entry
-keep class * implements de.robv.android.xposed.IXposedHookLoadPackage { *; }

# These are reached from the module entry and receiver registration path.
-keep class io.github.xiaotong6666.fusehide.StatusBroadcastReceiver { *; }
-keep class io.github.xiaotong6666.fusehide.MainThreadTask { *; }
