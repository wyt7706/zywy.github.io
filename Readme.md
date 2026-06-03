# ersc.dll 逆向分析报告

> **分析日期**: 2026-06-03  
> **文件路径**: C:\Users\zywy\Desktop\新建文件夹\ersc.dll  
> **文件大小**: 7,606.52 KB (7,789,072 字节)  
> **SHA256**: `28D1E82B6E06A37F47689AB9147E48AAE4C8BE1ADB4A8CF369E89BE53FDDC2BC`  

---

## 1. 基本信息摘要

| 属性 | 值 |
|------|------|
| **文件名** | `ersc.dll` |
| **描述** | **Elden Ring Seamless Co-op mod v3** — 艾尔登法环无缝联机 Mod 核心 DLL |
| **开发者** | `Yui` (YuiKeyNexus) |
| **架构** | x64 (PE32+) |
| **保护** | **Themida / WinLicense** (商业级强保护) |
| **导出函数** | `modengine_ext_init` (序号 1) |
| **PDB路径** | `C:\Users\Yui\source\repos\ersc\x64\Release\ersc.pdb` |
| **子系统** | 0 (未知 — 通常为 DLL 使用) |

---

## 2. PE 结构分析

### 2.1 文件头

```
DOS Header:          Valid (MZ)
PE Signature:        Valid (PE\0\0)
Machine:             0x8664 (x64)
Number of Sections:  16
Characteristics:     0x2022 (DLL | Executable)
Optional Header:     PE32+ (64-bit)
AddressOfEntryPoint: 0x0009A800
```

### 2.2 节表分析

| 节名称 | 虚拟大小 | 原始大小 | 熵值 | 权限 | 说明 |
|--------|---------|---------|------|------|------|
| `.text` | 0x18C376 | 0x18C400 | **6.48** | CODE \| EXECUTE \| READ | **主代码 — 高熵，可能被加密/混淆** |
| `.rdata` | 0x853E4 | 0x85400 | 6.09 | INIT_DATA \| READ | 只读数据（字符串、RTTI 等） |
| `.data` | 0x809C | 0x2000 | 2.82 | INIT_DATA \| READ \| WRITE | 读写数据 |
| `.pdata` | 0xE2C8 | 0xE400 | 6.17 | INIT_DATA \| READ | 异常处理数据 |
| `.00cfg` | 0x38 | 0x200 | 0.49 | INIT_DATA \| READ | CFG (Control Flow Guard) |
| `.gxfg` | 0x31F0 | 0x3200 | 5.25 | INIT_DATA \| READ | 扩展 CFG |
| `.retplne` | 0x8C | 0x200 | 1.05 | 无 | Retpoline (Spectre 缓解) |
| `.tls` | 0x9 | 0x200 | 0.02 | INIT_DATA \| READ \| WRITE | **TLS 回调 — 反调试** |
| `_RDATA` | 0x1F4 | 0x200 | 4.22 | INIT_DATA \| READ | 附加只读数据 |
| `.rsrc` | 0xE8 | 0x200 | 2.35 | INIT_DATA \| READ | 资源 (仅空清单) |
| `.reloc` | 0x1440 | 0x1600 | 5.28 | INIT_DATA \| READ | 基址重定位 |
| `.edata` | 0x1000 | 0x200 | 0.81 | INIT_DATA \| READ | 导出表 |
| `.idata` | 0x1000 | 0x400 | 2.35 | INIT_DATA \| READ \| WRITE | 导入表 |
| `.tls` | 0x1000 | 0x200 | 0.28 | READ \| WRITE | 第二 TLS 段 |
| **`.themida`** | **0x546000** | **0x546000** | **6.51** | **CODE \| EXECUTE \| READ \| WRITE** | ⚠️ **Themida 加密壳 — ~5.4MB 加密代码** |
| `.reloc` | 0x1000 | 0x10 | 2.47 | READ | 第二重定位表 |

### 2.3 关键发现 - 保护特征

| 特征 | 说明 |
|------|------|
| **Themida/WinLicense** | `.themida` 节区，5.4MB 加密壳代码，高熵 (6.51) |
| **TLS 回调** | TLS 目录 RVA=0x0074DBA4, Size=0x00013B3C (~80KB) — 异常巨大，用于反调试 |
| **CFG** | Control Flow Guard 开启 |
| **Retpoline** | Spectre 缓解措施 |
| **高熵 `.text`** | 并非普通 C++ 编译结果，有进一步混淆 |
| **EXECUTE+READ+WRITE 权限** | `.themida` 节同时可执行、可读、可写 — 典型自修改代码特征 |

---

## 3. 导入 / 导出表

### 3.1 导出函数

| 序号 | 名称 | RVA |
|------|------|-----|
| 1 | `modengine_ext_init` | 0x00002B00 |

> ⚠️ `modengine_ext_init` 是此 DLL 的**唯一导出函数**，是 Mod Engine 框架的扩展初始化入口。

### 3.2 静态导入表 (Obfuscated by Themida)

导入表已被 Themida 混淆。解析出的 DLL 依赖：

| DLL | 可能用途 |
|-----|---------|
| `kernel32.dll` | Windows 核心 API (进程、内存、文件操作) |
| `USER32.dll` | Windows GUI 交互 |
| **`steam_api64.dll`** | **Steam API — 联机功能核心依赖** |
| `WS2_32.dll` | Windows Sockets 网络通信 |
| `ADVAPI32.dll` | 注册表、安全、服务控制 |
| `CRYPT32.dll` | 加密功能 (证书、CryptoAPI) |
| `WLDAP32.dll` | LDAP 协议 |
| `Normaliz.dll` | Unicode 规范化 |

> **注**: Themida 在运行时动态解析真正的 API 地址，静态导入表不完整且经过混淆。

---

## 4. 字符串分析 — 功能推断

### 4.1 核心身份标识

```
"Elden Ring Seamless Co-op mod by Yui [ YuiKeyNexus Version 3 ]"
"Seamless Coop %s - Fatal Error"
"ersc.dll"
"modengine_ext_init"
```

> ✅ **确认: 此 DLL 为艾尔登法环无缝联机 Mod 第 3 版的核心库。**

### 4.2 框架/项目名称

```
YuiKeyNexus3           — 主框架名称
YuiKeyBattleRoyale2    — 子模式: 大逃杀
YKEventFlagMan         — 事件标志管理器
YKNX3_*                — 大量 YuiKeyNexus3 功能枚举
SeamlessCoop           — 无缝联机会话标识
```

### 4.3 游戏内部模块 (CS:: 命名空间)

```
CSEventFlagMan         — 事件标志管理
CSFeMan                — FE (前端/UI) 管理
CSGameMan              — 游戏主管理器
CSGameDataMan          — 游戏数据管理
CSLockTgtMan           — 锁定目标管理
CSMapItemMan           — 地图物品管理
CSMenuMan              — 菜单管理
CSSessionManager       — 会话管理
CSWorldChrMan          — 世界角色管理
CSVoiceChatManager     — 语音聊天管理
CSRegulationManager    — 游戏规则/参数管理
CSPartyMemberInfo      — 队伍成员信息
CSPlayerIns            — 玩家实例
DelayGaugeViewParts    — BOSS 血量条 UI 组件
CSChrSet               — 角色设置
CSCheatDetectionSpider — 反作弊检测
```

### 4.4 联机会话管理

```
OPTIONSELECT_JOINWORLD           — 加入世界
OPTIONSELECT_LEAVEWORLD          — 离开世界
OPTIONSELECT_OPENWORLD           — 开放世界
OPTIONSELECT_LOCKWORLD           — 锁定世界
OPTIONSELECT_UNLOCKWORLD         — 解锁世界
OPTIONSELECT_STARTEVILSESSION     — 开始邪恶入侵会话
OPTIONSELECT_VIEWEVILSESSION      — 查看邪恶会话
OPTIONSELECT_SEEKEVILSESSION      — 寻找邪恶会话
OPTIONSELECT_LEAVEEVILSESSION     — 离开邪恶会话
OPTIONSELECT_CANCELBREAKINWORLD   — 取消入侵世界
OPTIONSELECT_BREAKINWORLD         — 入侵世界
OPTIONSELECT_CALLBREAKINSOS       — 入侵求救
OPTIONSELECT_BOSSRUSH             — BOSS 连战
OPTIONSELECT_EASYENEMYRUSH        — 简单敌人 Rush
OPTIONSELECT_MEDENEMYRUSH         — 中等敌人 Rush
OPTIONSELECT_HARDENEMYRUSH        — 困难敌人 Rush
OPTIONSELECT_INFENEMYRUSH         — 地狱敌人 Rush
OPTIONSELECT_GIVEEMBER            — 给予余火
OPTIONSELECT_TOGGLEPVP            — 切换 PVP
OPTIONSELECT_TOGGLEPVPTEAMS       — 切换 PVP 队伍
OPTIONSELECT_TOGGLEFRIENDLYFIRE   — 切换友军伤害
OPTIONSELECT_TOGGLEDRIEDFINGER    — 切换干缩手指
OPTIONSELECT_SHOWYKNX3PASSWORD    — 显示密码
OPTIONSELECT_RAPIDREENTRYRBREAKINWORLD — 快速重新入侵
```

### 4.5 Steam API 集成

```
steam_api64.dll
SteamAPI_GetHSteamPipe
SteamClient020                  — Steam 客户端 v020
SteamUser021                    — Steam 用户 v021
SteamFriends017                 — Steam 好友 v017
SteamMatchMaking009             — Steam 匹配 v009
SteamNetworking006              — Steam 网络 v006
SteamNetworkingMessages002      — Steam 网络消息 v002
SteamNetworkingUtils003         — Steam 网络工具 v003
SteamUtils010                   — Steam 工具 v010
STEAMAPPS_INTERFACE_VERSION008  — Steam 应用 v008
SteamSocketManager              — 内部 Socket 管理器
MTInternalThreadSteamSocketManager — 多线程 Socket 管理器
SteamConnectionManager          — 连接管理器
```

### 4.6 语音聊天系统

```
VoiceChatSteam                  — Steam 语音聊天
VoiceChatMemberRefInfo          — 语音成员引用信息
YuiNexus3VoiceChatAudioInputObj_%d — 音频输入对象
Play_VoiceChat                  — 播放语音
Stop_VoiceChat                  — 停止语音
Unable to create YuiNexus3 player audio object instance [%u] [error = %u]
```

### 4.7 游戏物品 (Mod Goods)

```
MODGOODSNAME_BREAKINITEM       — 入侵道具名称
MODGOODSDESC_BREAKINITEM       — 入侵道具描述
MODGOODSNAME_JOININGITEM       — 加入道具
MODGOODSNAME_LEAVINGITEM       — 离开道具
MODGOODSNAME_HOSTINGITEM       — 主机道具
MODGOODSDESC_DRIEDFINGERITEM   — 干缩手指道具
MODGOODSDESC_GAMERULECHANGEITEM — 游戏规则变更道具
MODGOODSDESC_ROTITEM01-05      — 腐败/变质道具
MODGOODSDESC_RUNEARCITEM       — 卢恩弯弧道具
MODGOODSNAME_EMBERITEM         — 余火道具
```

### 4.8 网络协议栈 (libcurl)

大量 HTTP/SOCKS/FTP/TFTP 相关字符串表明该 DLL 集成了 **libcurl 7.76.1**：

```
HTTP/1.1, HTTP/2, HTTP/3 支持
SOCKS4, SOCKS5 代理
SSL/TLS (Schannel)
FTP, TFTP, RTSP, IMAP, POP3, SMTP
Cookie, Alt-Svc, HTTP/2 framing
OAuth2, NTLM, Digest, Negotiate, Basic 认证
```

### 4.9 崩溃报告 (Crashpad)

集成了 Google Crashpad 崩溃报告框架：

```
crashpad::CrashReportDatabase
crashpad::CrashReportDatabaseWin
crashpad::CrashpadClient::StartHandler
crashpad::CrashpadClient
UnhandledExceptionHandler
\\.\pipe\crashpad_%lu_      — 命名管道
```

### 4.10 项目源文件结构

```
ersc/
├── ersc.cpp                          — 主入口
├── hooks/hooks.cpp                   — 钩子系统
├── signatures/signatures.cpp         — 特征码扫描
├── param/param.cpp                   — 参数系统
├── networking/networking.cpp         — 网络通信层
├── mod/
│   ├── cheat_detection_spider/       — 反作弊蜘蛛
│   ├── preferences/                  — 偏好设置
│   ├── voice_chat/                   — 语音聊天
│   └── message_repository/           — 消息仓库 (多语言)
├── cs/
│   ├── event_flag_man/               — 事件标志管理器
│   ├── session_manager/              — 会话管理器
│   ├── world_chr_man/                — 世界角色管理器
│   ├── game_man/                     — 游戏管理器
│   ├── game_data_man/                — 游戏数据管理器
│   ├── fe_man/                       — 前端管理器
│   ├── menu_man/                     — 菜单管理器
│   ├── lock_tgt_man/                 — 锁定目标管理器
│   ├── map_item_man/                 — 地图物品管理器
│   ├── lua_event_man/                — Lua 事件管理器
│   └── emk_system/                   — EMK 系统
├── seamless_session_manager/         — 无缝会话管理器
├── spectate/                         — 观战系统
├── battle_royale/                    — 大逃杀模式
├── buddy/                            — 伙伴系统
├── yui_nexus_3/                      — YuiNexus3 框架
└── game_memory_unlimiter/            — 游戏内存限制解除
```

---

## 5. 完整技术架构

```
┌─────────────────────────────────────────────────────────────┐
│                    ersc.dll 整体架构                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌───────────────────────────────────────┐                   │
│  │       Themida/WinLicense 保护层        │  ← 反调试/反篡改  │
│  │  ┌─────────────────────────────────┐  │                   │
│  │  │   modengine_ext_init (导出入口)   │  │  ← Mod Engine 入口 │
│  │  ├─────────────────────────────────┤  │                   │
│  │  │   ┌───────────────────────────┐ │  │                   │
│  │  │   │   YuiKeyNexus3 框架        │ │  │  ← 主业务逻辑    │
│  │  │   │  ├─ 无缝联机会话管理        │ │  │                   │
│  │  │   │  ├─ 入侵系统               │ │  │                   │
│  │  │   │  ├─ BOSS Rush 模式         │ │  │                   │
│  │  │   │  ├─ 大逃杀模式             │ │  │                   │
│  │  │   │  ├─ 语音聊天系统            │ │  │                   │
│  │  │   │  ├─ 观战系统               │ │  │                   │
│  │  │   │  └─ 伙伴系统               │ │  │                   │
│  │  │   └───────────────────────────┘ │  │                   │
│  │  ├─────────────────────────────────┤  │                   │
│  │  │   ┌───────────────────────────┐ │  │                   │
│  │  │   │   游戏引擎交互层            │ │  │  ← Mod 与游戏通信 │
│  │  │   │  ├─ 钩子系统 (hooks)       │ │  │                   │
│  │  │   │  ├─ 特征码扫描 (signatures) │ │  │                   │
│  │  │   │  ├─ 参数注入 (param)       │ │  │                   │
│  │  │   │  └─ 内存限制解除            │ │  │                   │
│  │  │   └───────────────────────────┘ │  │                   │
│  │  ├─────────────────────────────────┤  │                   │
│  │  │   ┌───────────────────────────┐ │  │                   │
│  │  │   │   网络层                    │ │  │  ← 通信协议栈    │
│  │  │   │  ├─ Steam Networking       │ │  │                   │
│  │  │   │  ├─ Steam Matchmaking     │ │  │                   │
│  │  │   │  └─ 内部 Socket 管理器     │ │  │                   │
│  │  │   └───────────────────────────┘ │  │                   │
│  │  ├─────────────────────────────────┤  │                   │
│  │  │   ┌───────────────────────────┐ │  │                   │
│  │  │   │   第三方库                  │ │  │                   │
│  │  │   │  ├─ libcurl 7.76.1        │ │  │  ← HTTP 客户端   │
│  │  │   │  ├─ crashpad               │ │  │  ← 崩溃报告      │
│  │  │   │  ├─ nlohmann_json v3.12.0 │ │  │  ← JSON 解析     │
│  │  │   │  └─ OpenSSL/Schannel      │ │  │  ← TLS 加密      │
│  │  │   └───────────────────────────┘ │  │                   │
│  │  └─────────────────────────────────┘  │                   │
│  └───────────────────────────────────────┘                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 6. 保护机制分析

### 6.1 Themida / WinLicense 保护特征

| 特征 | 严重程度 | 说明 |
|------|---------|------|
| `.themida` 节区 | ⚠️ **高** | 5.4MB 加密代码，执行时动态解密 |
| TLS 回调 | ⚠️ **高** | 80KB TLS 目录，用于反调试、反 VT |
| 高熵代码 | ⚠️ **高** | `.text` 节熵值 6.48，超出正常编译代码 |
| RWX 权限 | ⚠️ **高** | `.themida` 同时可写可执行 (自修改代码) |
| Anti-Debug | ⚠️ **高** | 反 DBG、反内存 dump、API hook 检测 |
| PDB 泄露 | ⚠️ **中** | 编译 PDB 路径暴露了完整源码结构 |
| 导入表混淆 | ⚠️ **中** | 静态导入表中函数名被隐藏 |

### 6.2 反作弊系统

```
CSCheatDetectionSpider — 内置反作弊检测"蜘蛛"
  └─ WhatIsPatchBytes() — 检查内存补丁
  └─ 检测内存修改、作弊引擎
```

---

## 7. 通信协议分析

### 7.1 联机协议栈

```
             ┌──────────────┐
             │  Elden Ring  │
             │  (eldenring.exe) │
             └──────┬───────┘
                    │ 游戏内部函数钩子
             ┌──────┴───────┐
             │   ersc.dll   │
             │  (本 DLL)     │
             └──────┬───────┘
                    │ Steam Networking
             ┌──────┴───────┐
             │ Steam 服务器  │
             │ (协调/匹配)    │
             └──────┬───────┘
                    │ P2P / Relay
             ┌──────┴───────┐
             │  玩家客户端   │
             │  (其他实例)    │
             └──────────────┘
```

### 7.2 会话流程

```
会话创建:
  Open World → Steam Lobby Create → 等待玩家加入
  
会话加入:
  Join World → Steam Lobby Search → Steam Lobby Join → 连接建立
  
入侵系统:
  Seek Evil Session → 入侵世界 (Break In) → PvP 对抗

通信:
  Steam Networking Messages (P2P)
  语音聊天: Steam Voice / 自定义 RTP
  状态同步: 世界状态、角色位置、BOSS 状态
```

---

## 8. 静态分析结论

### 8.1 功能总结

1. **🎮 核心功能**: 艾尔登法环无缝联机 Mod v3
2. **🔌 导出入口**: `modengine_ext_init` — Mod Engine 框架扩展
3. **🛡️ 保护**: Themida/WinLicense 强加密保护
4. **🌐 网络**: Steam API (Lobby + Networking + Voice)
5. **🔄 游戏集成**: 通过 hooks + signatures 注入游戏进程
6. **📡 HTTP**: libcurl 7.76.1 集成 (可能用于自动更新/鉴权)
7. **🗣️ 语音**: 内置 Steam 语音聊天
8. **⚔️ 子模式**: PvP 开关、入侵、BOSS Rush、大逃杀
9. **📊 崩溃报告**: Crashpad 集成
10. **🔍 反作弊**: 内置补丁检测 (CheatDetectionSpider)

### 8.2 风险提示

| 风险 | 说明 |
|------|------|
| **反调试** | Themida 保护会检测调试器并可能触发反制措施 |
| **进程注入** | DLL 通过 Mod Engine 注入 `eldenring.exe` 进程 |
| **内存操作** | 直接读写游戏进程内存、安装钩子 |
| **网络通信** | 通过 Steam 网络进行 P2P 通信 |
| **反篡改** | WinLicense 内建完整性校验和防篡改机制 |

### 8.3 建议的进一步分析工具

| 工具 | 用途 |
|------|------|
| **x64dbg** | 动态调试 (需先过 Themida 反调试) |
| **ScyllaHide** | 过 Themida 反调试插件 |
| **IDA Pro / Ghidra** | 反汇编静态分析 (需先脱壳) |
| **Process Hacker** | 监控运行时行为 |
| **API Monitor** | 监控 API 调用 |
| **WireShark** | 分析网络通信 (如果存在 HTTP 通信) |
| **TitanHide** | 内核级反反调试 |

> ⚠️ **脱壳难度**: Themida/WinLicense 是商业级保护，有成熟的 Anti-Debug、Anti-VM、Anti-Dump、API obfuscation 机制。脱壳需要先绕过 TLS 反调试回调，再处理代码解密。推荐在专门的分析环境（Win 7 VM + x64dbg + ScyllaHide）中进行动态分析。

---

## 9. 附录

### A. 关键字符串索引

```
[Class RTTI]
  .?AVCSVoiceChatManager@CS@@
  .?AVCrashReportDatabase@crashpad@@  
  .?AVSteamConnectionManager@DLNW3D@@
  .?AVVoiceChatSteam@DLNR3D@@
  .?AVPlayerIns@CS@@
  .?AVWorldBlockRes@CS@@
  .?AVEcTestChrDead@CS@@
  .?AVDelayGaugeViewParts@CS@@

[Source Paths]
  C:\Users\Yui\source\repos\ersc\x64\Release\ersc.pdb
  ../src/951b70517d-61636f7b86.clean/client/... (crashpad)
  ersc/hooks/hooks.cpp
  ersc/signatures/signatures.cpp
  ersc/networking/networking.cpp

[Version Info]
  libcurl 7.76.1
  nlohmann_json v3.12.0
  Steam Client v020 / SteamFriends v017 / SteamMatchMaking v009
```

### B. 检测到的第三方库

| 库 | 用途 | 版本 |
|----|------|------|
| **libcurl** | HTTP/HTTPS/FTP/SOCKS 网络请求 | 7.76.1 |
| **crashpad** | 崩溃报告与收集 | Google Chromium 项目 |
| **nlohmann/json** | JSON 序列化/反序列化 | v3.12.0 |
| **Schannel (SSPI)** | Windows SSL/TLS 加密 | Windows 内置 |
| **OpenSSL (部分)** | 加密算法 (RSA, SHA, ECDSA) | 静态链接 |
| **zlib** | 数据解压缩 (inflate/deflate) | 推测 |
| **Steam API** | Steamworks SDK 联机 | 多接口版本混用 |

### C. 文件熵值说明

高熵值（>6.5）节区表明：
- 代码经过加密/压缩/混淆
- 不是标准 C/C++ 编译器的输出
- `.themida` 节 (6.51) 和 `.text` 节 (6.48) 均需在运行时由 Themida 解包器解密

---

> **报告结束**  
> 本文档仅供安全研究与逆向工程学习使用。分析对象为公开可下载的游戏 Mod 文件。
