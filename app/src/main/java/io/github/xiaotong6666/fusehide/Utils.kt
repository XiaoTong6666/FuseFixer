package io.github.xiaotong6666.fusehide

object Utils {
    init {
        System.loadLibrary("fusehide")
    }

    @JvmStatic
    external fun rmdir(path: String): Int

    @JvmStatic
    external fun unlink(path: String): Int

    @JvmStatic
    external fun mkdir(path: String): Int

    @JvmStatic
    external fun rename(oldPath: String, newPath: String): Int

    @JvmStatic
    external fun create(path: String): Int
}
