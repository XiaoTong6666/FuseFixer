# FuseFixer

## 简介

FuseFixer 是一个面向 Android 12+ 的 LSPosed 模块与调试工具，用于在 `MediaProvider` 进程内注入 native hook，修复可忽略码点（如零宽空格/零宽连字符）导致的 `/sdcard/Android/{data,obb}/$package` 访问绕过问题，并提供简易自测界面。

作用域为 `com.android.providers.media.module` / `com.google.android.providers.media.module`，重启作用域进程后生效。

#### 模块工作流：

1. LSPosed 通过 `xposed_init` 加载 `Entry`。
2. 当目标进程命中 MediaProvider 包名时，加载 `libfusefixer.so`。
3. native 层定位 `libfuse_jni.so` 关键符号并安装 hook。
4. App 侧通过广播握手确认 hook 状态，并在 UI 中执行路径调试动作。

#### 主要能力：

- LSPosed 模块入口与作用域声明（MediaProvider 双包名）。
- Native hook 注入与状态广播确认。
- Path 调试按钮：`Stat` / `Access` / `List` / `Open` / `Get Con`。
- Unicode 辅助能力：支持 `\\uXXXX` 输入与 `ZWJ` 插入。
- `StructStat` 格式化输出（权限、inode、device、uid/gid）。
- `.gnu_debugdata` 的 XZ 解压与符号解析（含 APK 嵌套 ELF 映射场景）。

#### 生效条件：

- 如果内核支持 fuse bpf（`getprop ro.fuse.bpf.is_running` 为 `1`），模块可直接生效。
- 如果内核不支持 fuse bpf（`getprop ro.fuse.bpf.is_running` 为 `0`），需要配合 vold app data 隔离才有效。
- vold app data 隔离可通过 HMA 开启，或执行 `setprop persist.sys.vold_app_data_isolation_enabled 1`。
- 应用界面会显示 fuse bpf 与 app data isolation 当前状态，便于确认环境。

#### 说明：

1. fuse bpf 在较低版本内核（常见如 Android 12 的 5.10 及以下）通常不支持，较高版本一般支持，但仍取决于厂商是否启用相关选项。
2. 如果已确认 fuse bpf 启用，则无需再开启 vold app data 隔离。

## 使用与自测

#### 发布地址：

- https://github.com/XiaoTong6666/FuseFixer/releases

#### 安装与使用：

1. 安装 APK。
2. 在 LSPosed 中启用 FuseFixer 模块。
3. 勾选作用域：`com.android.providers.media.module`、`com.google.android.providers.media.module`。
4. 重启作用域进程或重启设备。
5. 打开 App，确认 `Module status` 已显示 hooked；可点击状态行触发重新检查。
6. 在路径输入框执行 `Stat/Access/List/Open/Get Con` 进行验证。

#### 自测说明：

1. 自测界面包含路径输入框、操作按钮和结果输出。默认路径是当前用户的 `/storage/emulated/$userId/Android/\u200ddata`（默认带一个 ZWJ）。
2. 按钮说明：`Stat` / `Access` / `List` / `Open` / `Get Con` 会对当前路径执行对应文件系统操作并追加输出；`Clear` 清空输出；`Reset` 恢复默认路径；`Insert ZWJ` 会在输入框末尾追加 `\u200d`；`Copy All` 复制全部结果；`Self Data` 输出当前应用的 `external files dir`。
3. 测试 `/storage/emulated/$userId/Android/data` 的 `List`：返回 `None` 表示 `list` 失败或不可列；可列时会显示数量和文件列表。该路径一般可 `Stat` / `Access`，通常无需重点测这两项。
4. 测试 `/storage/emulated/$userId/Android/data/$pkg` 的 `Access` / `Stat` / `Open`：返回 `OK` 或 `EACCES` 通常表示目录存在（包存在）；返回 `ENOENT` 表示目录不存在；其他错误可能与 ROM/内核改动有关。
5. 请将 `$userId` 替换为实际用户 ID（主用户通常为 `0`），`$pkg` 替换为待测包名。
6. 可在 `/storage/emulated/$userId/` 之后任意位置插入 ZWJ 或其他零宽字符（ZWC）验证绕过修复。支持直接输入 Unicode 转义 `\uXXXX`（仅该形式会被自动解码；`$'\uXXXX'`、`\xXX` 不会自动转义）。
7. 输出中的路径会把非 ASCII 可打印字符转义为 `\uXXXX` 形式，便于比对日志。
8. 自测功能在模块启用前后都可使用：启用后预期是“带 ZWC 的路径访问结果”与“移除所有 ZWC 后路径访问结果”一致；未启用时可用于观察系统原始行为。

#### 构建：

```bash
./gradlew assembleDebug assembleRelease
```

## 其他

#### 许可证：

- `app/src/main/cpp/third_party/xz-embedded/*` 来自 xz-embedded，文件头声明 `SPDX-License-Identifier: 0BSD`。
- 本仓库整体采用 MIT License（见 `LICENSE`）。

#### 问题反馈：

- 提交 Issue 时建议附上：设备型号、Android 版本、ROM、`MediaProvider` 的 Apk、复现路径、关键 logcat。

#### 致谢：

特别感谢 5ec1cff 佬提供的原型模块作为参考以及技术指导支持，谢谢喵。

#### 免责声明：

本项目用于学习、调试与兼容性研究。请仅在你有权限的设备与环境中使用，并自行承担相关风险。
