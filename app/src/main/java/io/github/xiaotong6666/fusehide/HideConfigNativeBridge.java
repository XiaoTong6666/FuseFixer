package io.github.xiaotong6666.fusehide;

public final class HideConfigNativeBridge {
    static {
        System.loadLibrary("fusehide");
    }

    private HideConfigNativeBridge() {}

    public static native boolean getDefaultEnableHideAllRootEntries();

    public static native String[] getDefaultHideAllRootEntriesExemptions();

    public static native String[] getDefaultHiddenRootEntryNames();

    public static native String[] getDefaultHiddenRelativePaths();

    public static native String[] getDefaultHiddenPackages();

    public static native boolean getCurrentEnableHideAllRootEntries();

    public static native String[] getCurrentHideAllRootEntriesExemptions();

    public static native String[] getCurrentHiddenRootEntryNames();

    public static native String[] getCurrentHiddenRelativePaths();

    public static native String[] getCurrentHiddenPackages();

    public static native void applyHideConfig(
            boolean enableHideAllRootEntries,
            String[] hideAllRootEntriesExemptions,
            String[] hiddenRootEntryNames,
            String[] hiddenRelativePaths,
            String[] hiddenPackages);
}
