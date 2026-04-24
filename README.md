# FuseHide

## 简介

FuseHide 是一个面向 Android 12+ 的 LSPosed/Xposed 模块与 MediaProvider/FUSE 调试工具。

当前实现会在 `MediaProvider` 进程中加载 `libfusehide.so`，并在 `libfuse_jni.so` 加载后安装 native hook，用于按运行时配置对指定应用隐藏 `/storage/emulated/0`（`/sdcard`）下的普通路径，同时保留对 `Android/data`、`Android/obb` 相关 Unicode 场景的调试与修复逻辑。

当前版本同时包含 `/storage/emulated/0/Android/{data,obb}` 可忽略码点绕过修复与运行时可配置的普通路径隐藏策略：

- 对指定包名对应的 UID 生效。
- 支持隐藏 `/storage/emulated/0` 下的一级目录名，例如默认的 `xinhao`、`MT2`。
- 支持配置相对路径隐藏，例如 `Download/private` 这类嵌套目录。
- 支持“隐藏所有一级目录”的压力测试模式，并允许配置例外项。
- 支持在应用侧编辑配置，并将配置热同步到已注入的 MediaProvider 进程。

默认作用域为：

- `com.android.providers.media.module`
- `com.google.android.providers.media.module`

启用模块后，需要重启 MediaProvider 作用域进程或重启设备。

## 工作原理

### 模块加载流程

1. LSPosed 通过 `assets/xposed_init` 加载 `io.github.xiaotong6666.fusehide.Entry`。
2. `Entry` 在 `handleLoadPackage()` 中仅对 MediaProvider 包名生效。
3. 命中作用域后，`Entry` 直接在目标进程中执行 `System.loadLibrary("fusehide")`。
4. native 层通过 `assets/native_init` 暴露 `native_init()`，向宿主返回 `PostNativeInit` 回调。
5. `PostNativeInit()` 在检测到 `libfuse_jni.so` 被加载后调用 `InstallFuseHooks()`。
6. Java 层与注入进程通过广播、`HideConfigProvider`、`HideConfigRequestReceiver` 同步状态与隐藏配置。

### 普通路径隐藏说明

普通路径隐藏并不依赖 fuse-bpf。

FuseHide 对 `/storage/emulated/0` 下普通目录的隐藏，是直接在 MediaProvider 的 FUSE 处理链路中完成的：

- `WrappedIsAppAccessiblePath()` 在路径访问判断处按 UID 与路径策略拒绝隐藏目标。
- `WrappedReplyEntry()` 在隐藏目标 lookup 命中后，优先通过 `fuse_reply_err(ENOENT)` 把 positive lookup 改成不存在。
- `WrappedReplyBuf()` 作为目录枚举最终出口，识别多种 FUSE reply payload 形式并过滤隐藏项。
- `WrappedShouldNotCache()` 对隐藏子树强制返回 `true`，避免 positive dentry/file-cache 被跨 UID 复用。
- `WrappedReplyAttr()` 在当前 `getattr` 命中隐藏子树时把 attr cache timeout 置 0。
- `ScheduleHiddenEntryInvalidation()`、`ScheduleSpecificEntryInvalidation()`、`ScheduleHiddenInodeInvalidation()` 主动压掉 entry 与 inode cache，减少 positive cache 复活导致的泄漏。

因此，对普通路径隐藏而言，核心依赖是 `libfuse_jni.so` 内部 FUSE handler 与 reply 链路的 hook，而不是内核是否启用了 fuse-bpf。

项目保留了 `is_bpf_backing_path` 相关 hook。该部分用于 `Android/data`、`Android/obb` 这类特殊 pass-through / backing 路径场景的 Unicode 相关处理；这与普通路径隐藏不是同一条依赖链路。

### Android/data 场景说明

`/storage/emulated/0/Android/data` 与 `/storage/emulated/0/Android/obb` 不属于本项目用于普通目录隐藏的目录枚举过滤链路。

MediaProvider 对这两类路径使用单独的访问控制路径。当前仓库中可直接对应的证据包括：

- Java 调试层会在可调试构建中 hook 并记录 `MediaProvider.isUidAllowedAccessToDataOrObbPathForFuse()` 的返回值。
- native 层保留了 `is_bpf_backing_path`、`is_package_owned_path`、`EqualsIgnoreCase` 相关 hook 安装逻辑。
- 上游 MediaProvider/FuseDaemon 实现对 `Android/data`、`Android/obb` 使用 backing path 判定与后续专用处理，而不是普通公共目录的通用目录过滤路径。

本项目在这部分的处理是修复特殊路径判断中的 Unicode 可忽略码点绕过，并保持 `Android/data`、`Android/obb` 的访问判定落入 MediaProvider 的专用访问控制路径。

当前应用界面会展示这些系统属性：

- `ro.fuse.bpf.is_running`
- `persist.sys.vold_app_data_isolation_enabled`
- `external_storage.sdcardfs.enabled`

当前代码中的界面提示逻辑是：当 `ro.fuse.bpf.is_running=false` 且 `persist.sys.vold_app_data_isolation_enabled=false` 时，界面显示 `App data isolation is required to fix Android/data access.`，并显示 `setprop persist.sys.vold_app_data_isolation_enabled 1`。

这部分内容对应的是当前应用的诊断输出与调试提示。

## 当前主要能力

### 运行时隐藏配置

配置项包括：

- `enableHideAllRootEntries`：隐藏 `/storage/emulated/0` 下所有一级目录，默认关闭。
- `hideAllRootEntriesExemptions`：隐藏所有一级目录时的例外项，默认保留 `Android` 可见。
- `hiddenRootEntryNames`：要隐藏的一级目录名，默认包括 `xinhao`、`MT2`。
- `hiddenRelativePaths`：要隐藏的相对路径，默认为空，适合嵌套目标，例如 `Download/private`。
- `hiddenPackages`：对哪些包名对应的 UID 生效，当前默认包括：
  `com.eltavine.duckdetector`、`io.github.xiaotong6666.fusehide`、`io.github.a13e300.fusefixer`。

默认值来自 native 层的 `HideConfigNativeBridge`，Java/Kotlin 层通过 `HideConfigDefaults` 读取。

配置保存后可通过广播热加载到 MediaProvider。注入进程优先通过 `HideConfigProvider` 读取配置；如果 provider 暂不可用，则通过 `HideConfigRequestReceiver` 请求配置。当前请求超时为 3 秒。注入进程还会在以下系统阶段触发配置重试：

- `Intent.ACTION_LOCKED_BOOT_COMPLETED`
- `Intent.ACTION_BOOT_COMPLETED`
- `Intent.ACTION_USER_UNLOCKED`

### Hook 覆盖范围

native 层会尝试覆盖以下链路：

- 路径访问判断：`is_app_accessible_path`
- Android/data backing 判断：`is_bpf_backing_path`
- 包路径判断：`is_package_owned_path`
- 字符串比较：`strcasecmp`、`EqualsIgnoreCase`
- lookup：`pf_lookup`、`pf_lookup_postfilter`、`fuse_reply_entry`
- getattr：`pf_getattr`、`fuse_reply_attr`
- 目录枚举：`pf_readdir`、`pf_readdirplus`、`pf_readdir_postfilter`、`do_readdir_common`、`GetDirectoryEntries`、`addDirectoryEntriesFromLowerFs`、`fuse_reply_buf`
- 创建、删除与重命名：`pf_mkdir`、`pf_mknod`、`pf_create`、`pf_unlink`、`pf_rmdir`、`pf_rename`
- lower-fs 兜底：`stat`、`lstat`、`getxattr`、`lgetxattr`、`mkdir`、`mknod`、`open`、`__open_2`
- 缓存控制与失效：`ShouldNotCache`、`fuse_lowlevel_notify_inval_entry`、`fuse_lowlevel_notify_inval_inode`
- 错误码修正：`fuse_reply_err`

这些 hook 先通过符号、`.gnu_debugdata`、重定位槽和布局推导解析；解析不足时再回退到设备 profile offset。

### 目录枚举过滤

目录隐藏不是只拦单个 lookup。FuseHide 会在多个层级过滤目录项：

1. `GetDirectoryEntries()` 返回的 native vector。
2. `addDirectoryEntriesFromLowerFs()` 追加的 lower-fs 目录项。
3. `pf_readdir` / `pf_readdirplus` / `pf_readdir_postfilter` 的上下文记录。
4. `WrappedReplyBuf()` 中的最终 FUSE wire payload。

`WrappedReplyBuf()` 是最后一层过滤点。它会结合 pending readdir context、inode-path cache、最近可见父目录路径等信息过滤隐藏项。

### 缓存与错误码泄漏处理

为了避免“路径已经隐藏，但缓存或错误码仍然暴露目标存在”，native 层还处理了：

- hidden subtree inode 跟踪。
- inode 到 path 的缓存。
- 最近隐藏父路径记录，用于嵌套相对路径的 fallback 过滤。
- hidden lookup 命中后的 entry/inode invalidation。
- hidden getattr 的 attr timeout 置 0。
- hidden entry 的 entry timeout / attr timeout 置 0。
- `EEXIST`、`EISDIR`、`ENOTEMPTY`、`ENOTDIR` 等存在性错误码 remap。
- create / mkdir / rename / unlink / rmdir 路径中的隐藏目标短路。

## 使用方法

### 安装

1. 安装 APK。
2. 在 LSPosed 中启用 FuseHide。
3. 勾选作用域：
   - `com.android.providers.media.module`
   - `com.google.android.providers.media.module`
4. 重启 MediaProvider 作用域进程，或直接重启设备。
5. 打开 FuseHide，确认 Hook 状态显示已 Hook。

### 配置隐藏策略

在“配置”页面可以编辑：

- 是否隐藏所有一级目录。
- 一级目录例外。
- 隐藏目标。
- 隐藏包名。

“隐藏目标”每行一条：

```text
xinhao
MT2
Download/private
```

当前应用中的解析规则如下：

- 不含 `/` 的值会作为一级目录名处理，进入 `hiddenRootEntryNames`。
- 含 `/` 的值会作为相对路径处理，进入 `hiddenRelativePaths`。
- 路径前后的 `/` 会被规范化。
- 隐藏策略只对 `hiddenPackages` 中包名对应的 UID 生效。

按钮说明：

- “保存”：只保存到 FuseHide 应用本地配置。
- “应用”：保存并向 MediaProvider 作用域广播重新加载配置。
- “刷新已应用配置”：从已注入的 MediaProvider 进程读取当前 native 配置快照。
- “恢复默认值”：恢复源码内置默认隐藏配置到编辑器。

### 路径检测

“检测”页面提供直接文件系统测试：

- `Stat`
- `Access`
- `List`
- `Open`
- `Get Con`
- `Create`
- `Mkdir`
- `Rename/Move`
- `Rmdir`
- `Unlink`
- `All PKG`
- `Self Data`
- `Insert ZWJ`

路径输入支持 `\uXXXX` 形式的 Unicode 转义。输出会把非 ASCII 字符转成 `\uXXXX`，便于和 logcat 对照。

### 建议验证方式

以默认配置为例，目标应用包名命中 `hiddenPackages` 后：

1. 在 `/storage/emulated/0` 下创建 `xinhao` 或 `MT2`。
2. 在目标应用上下文中访问该路径。
3. 预期：
   - `lookup/stat/access/open` 类操作表现为不存在或不可访问。
   - `list /storage/emulated/0` 不应列出隐藏目录项。
   - 重复访问后不应因为 dentry / inode cache 恢复可见。
4. 对嵌套路径，例如 `Download/private`：
   - 父目录 `Download` 应保持可见。
   - `Download` 的目录枚举中应过滤 `private`。
   - 直接访问 `Download/private` 应被隐藏。

## 构建

```bash
./gradlew assembleDebug assembleRelease
```

构建要求以当前 Gradle 配置为准。当前仓库使用的关键版本包括：

- Gradle Wrapper `9.4.1`
- Android Gradle Plugin 9 系列
- JDK 17+
- Android SDK / NDK / CMake

仓库中的 GitHub Actions 工作流会构建 debug 与 release APK，并上传 artifact；在主分支发布流程中还会创建 GitHub Release。

## 日志与排错

建议过滤：

```bash
adb logcat -s FuseHide
```

反馈问题时建议提供：

- 设备型号
- Android 版本 / ROM 版本
- Kernel 版本
- MediaProvider APK 或版本信息
- `ro.fuse.bpf.is_running`
- `persist.sys.vold_app_data_isolation_enabled`
- 目标路径与目标包名
- FuseHide 配置截图或配置文本
- 关键 logcat

## 发布地址

- https://github.com/XiaoTong6666/FuseHide/releases

## 许可证

- `app/src/main/cpp/third_party/xz-embedded/*` 来自 xz-embedded，文件头声明 `SPDX-License-Identifier: 0BSD`。
- 本仓库整体采用 Apache License 2.0，详见 [LICENSE](LICENSE)。

## 致谢

特别感谢 5ec1cff 佬提供的原型模块作为参考以及技术指导支持，谢谢喵。

## 免责声明

本项目仅用于学习、调试、兼容性研究与个人设备实验。请仅在你有权限的设备与环境中使用，并自行承担相关风险。
