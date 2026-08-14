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

package io.github.xiaotong6666.fusehide.config;

public final class HideConfigNativeBridge {
    static {
        try {
            System.loadLibrary("fusehide");
        } catch (UnsatisfiedLinkError e) {
            // Expected in Zygisk mode; loaded by the wrapper.
        }
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

    public static native String[] getCurrentPackageRulePackages();

    public static native String[] getCurrentPackageRuleHiddenRootEntryNames();

    public static native String[] getCurrentPackageRuleHiddenRelativePaths();

    public static native void applyHideConfig(
            boolean enableHideAllRootEntries,
            String[] hideAllRootEntriesExemptions,
            String[] hiddenRootEntryNames,
            String[] hiddenRelativePaths,
            String[] hiddenPackages,
            String[] packageRulePackages,
            String[] packageRuleHiddenRootEntryNames,
            String[] packageRuleHiddenRelativePaths);

    // Package add/remove can change the effective hide rule for an already-seen uid even when the
    // serialized config is unchanged.
    public static native void notifyPackageSetChanged(String reason);
}
