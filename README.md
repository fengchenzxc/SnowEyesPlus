# SnowEyesPlus

`SnowEyesPlus` 是在 `SnowEyes-v0.3.0` 基础上持续演进出来的 MV3 浏览器插件版本。  
相较于 `SnowEyes v0.3.0`，`SnowEyesPlus` 不再只是“前端信息收集 + 基础指纹嗅探”，而是扩展为：

- 信息收集
- 统一指纹识别
- DOM XSS 检测
- 漏洞报告生成与管理
- Console 验证助手
- 一键 PoC 复现
- AI 误报研判与持续对话
- 调试与证据链展示

项目当前定位已经从“单体扫描插件”升级为“前端资产与 DOMXSS 审计工作台”。

## 1. 与 SnowEyes v0.3.0 的对比

### 1.1 版本定位

| 维度 | SnowEyes v0.3.0 | SnowEyesPlus |
| --- | --- | --- |
| 扩展名 | 雪瞳 | SnowEyesPlus |
| Manifest 版本号 | `0.3.0` | `1.0.0` |
| 代码形态 | 单体、压缩后源码风格 | 可维护源码 + 模块拆分 |
| 主要目标 | 信息搜集、基础指纹、网站解析 | 信息搜集 + 指纹识别 + DOMXSS + 报告 + AI + 调试 |
| 页面导航 | `scanner / fingerprint / analysis / config` | `scanner / report / fingerprint / analysis / debug / config` |

### 1.2 能力差异

| 能力 | SnowEyes v0.3.0 | SnowEyesPlus |
| --- | --- | --- |
| 页面信息收集 | 有 | 保留并增强 |
| 多 frame 扫描 | 有 | 保留并增强 |
| 基础 Header/Cookie 指纹 | 有 | 保留 |
| 第三方 JS/构建器识别 | 有 | 保留 |
| 网站解析 | 有 | 保留 |
| DOM XSS 检测 | 无 | 新增 |
| 漏洞报告中心 | 无 | 新增 |
| 报告详情页 | 无 | 新增 |
| Console 动态验证助手 | 无 | 新增 |
| 一键 PoC 复现 | 无 | 新增 |
| AI 误报研判 | 无 | 新增 |
| AI 持续对话 | 无 | 新增 |
| 调试页 | 无 | 新增 |
| 外部大规模指纹库 | 无 | 新增 |
| Wappalyzer/kscan/webapp 融合 | 无 | 新增 |
| 指纹误报压制模型 | 无 | 新增 |

### 1.3 架构差异

`SnowEyes v0.3.0` 的核心问题是：

- `background.js`、`content.js`、`popup.js` 都是大体量单体逻辑。
- 指纹识别能力分散在不同位置，扩展难度高。
- 没有统一漏洞报告数据结构。
- 没有漏洞验证、复现、AI 分析这类后续工作流。
- 旧版源码大部分呈现为压缩/构建后的单文件风格，可读性和可维护性较差。

`SnowEyesPlus` 的重构方向是：

- 提取统一 Report Schema，收敛报告字段漂移。
- 将背景页职责拆分为 store / AI / DOMXSS assist / PoC trigger。
- 提取 `fingerprint-core.js` 作为 content/background 共用引擎。
- 将“检测 -> 报告 -> 验证 -> 复现 -> AI 研判”串成完整闭环。
- 将 UI 从只看扫描结果，升级为支持报告详情、批量导出、调试与交互验证的工作台。

## 2. SnowEyesPlus 的主要更新

### 2.1 新增 DOM XSS 检测链路

`SnowEyesPlus` 在 `content.js` 中新增了 DOM XSS 语义检测与链路整理能力，能够输出：

- `Source 点`
- `Sink 点`
- `Source-Sink 链路`
- `payloadHint / payloadReason / payloadProfile`
- `EXP`
- `修复建议`

这意味着结果不再只是“命中一个模式”，而是会转成结构化漏洞报告。

### 2.2 新增漏洞报告中心

插件新增了完整的 `report` 页面，支持：

- 漏洞列表查看
- 按严重级别筛选
- 单条删除
- 批量勾选/删除
- 全量复制
- 导出全部
- 导出已选
- 报告详情弹层查看

这部分把扫描结果从“临时 UI 状态”变成了“可存储、可导出、可继续分析”的资产。

### 2.3 新增 Console 验证助手

对 DOM XSS 报告新增了 Console 动态验证模式：

- 在目标页面动态监控 sink 命中
- 使用低噪声 probe payload 做验证
- 输出验证结论、风险标签、payload 依据、sink 片段、尝试记录
- 支持复制 Console 脚本，方便手工复核

这解决了“扫描命中后如何快速确认是否真实可利用”的问题。

### 2.4 新增一键复现（主动注入）

对 DOM XSS 报告新增 PoC 主动复现能力：

- 根据 source 类型自动推断注入入口
- 尝试 query/hash/route/input 等不同注入方式
- 按 sink 场景自动挑选 payload
- 对 href/location 类 sink 支持辅助点击

这让插件具备了从“发现问题”走到“复现问题”的能力。

### 2.5 新增 AI 误报研判与 AI 会话

新增 AI 服务层，支持：

- 对单条漏洞报告做误报研判
- 返回 `verdict / confidence / reasons / recommendation`
- 基于当前报告进入持续对话
- 支持本地启发式 / Codex / DeepSeek / GLM 等 provider 配置

这使插件从“扫描工具”进一步向“辅助分析平台”演进。

### 2.6 指纹识别能力大幅升级

相较于 `v0.3.0` 只有基础 Header/Cookie/Analytics 识别，`SnowEyesPlus` 增加了统一指纹引擎：

- 内置基础规则库
- `finger.json`
- `kscan_fingerprint.json`
- `webapp.json`
- `apps.json`（Wappalyzer）

统一引擎支持：

- Header / Body / Title / Cookie / Meta / Script / JS Probe / Env / Favicon Hash 多信号识别
- kscan/ARL 风格表达式规则归一化
- Wappalyzer 风格 `implies / excludes / version` 处理
- content/background 共用同一套识别逻辑
- 指纹缓存与统一编译
- 指纹来源、评分、置信度、匹配字段展示

### 2.7 新增误报压制机制

针对大指纹库带来的误报问题，`SnowEyesPlus` 新增了误报压制专项：

- 同类指纹合并
- 名称归一化去重
- 互斥规则增强
- body 单弱特征更严降权
- 通用资源名弱化
- 锚点流行度惩罚
- 更具体命中优先保留

这让大库识别从“能识别更多”进一步提升到“能识别更多且更稳”。

### 2.8 新增调试页

`debug` 页面用于展示内部扫描与 DOM XSS 推断过程，便于排查：

- 扫描概要
- 发现 JS
- 成功/失败抓取的 JS
- DOMXSS 候选 sink
- Source 推断记录
- 过滤原因
- 最终报告链路

这对规则调试、误报分析、现场排障都很关键。

## 3. 主要重构点

### 3.1 单体背景页拆分为服务化结构

`background.js` 不再独自承载所有职责，而是依赖多个服务模块：

- `report-store.js`
- `ai-service.js`
- `domxss-assist.js`
- `poc-trigger.js`
- `fingerprint-core.js`

这样做的收益：

- 业务边界更清楚
- DOMXSS、AI、报告、指纹互不缠绕
- 更容易定位问题和继续扩展

### 3.2 提取统一 Report Schema

新增：

- `report-schema-core.js`
- `report-schema.module.js`

作用：

- 统一报告字段定义
- 统一 severity 处理
- 统一文本长度限制
- 统一 report id 生成
- 统一 normalize 入口

这解决了 content/background/popup 三处报告字段漂移问题。

### 3.3 提取共享指纹引擎

新增：

- `fingerprint-core.js`

它把以下内容集中在一起：

- 规则归一化
- 表达式解析
- 评分与置信度计算
- Wappalyzer 兼容处理
- 外部库加载与编译
- 指纹去重/合并/互斥/降噪

`content.js` 和 `background.js` 不再各自维护一份逻辑，从而降低重复代码与行为漂移。

### 3.4 UI 从“结果面板”升级为“工作流面板”

`v0.3.0` 的 popup 以扫描结果为中心。  
`SnowEyesPlus` 的 popup 已升级为完整工作流界面：

- 结果浏览
- 报告管理
- 详情查看
- Console 验证
- PoC 触发
- AI 研判
- 调试查看

并且 UI 已进行了多轮紧凑化和信息密度优化，更适合高频使用。

### 3.5 从压缩构建产物转向可维护源码

`v0.3.0` 的 `background.js / content.js / popup.js` 基本表现为压缩后的一体化脚本。  
`SnowEyesPlus` 则已经转成可维护源码形态，并把增量逻辑拆到了独立模块中。

这对后续继续做：

- DOMXSS 扩展
- 指纹引擎迭代
- UI 继续重构
- AI 接口替换
- 报告导出增强

都非常重要。

## 4. 当前目录结构

```text
SnowEyesPlus/
├── manifest.json
├── background.js
├── content.js
├── popup.html
├── popup.js
├── popup.css
├── fingerprint-core.js
├── report-schema-core.js
├── report-schema.module.js
├── report-store.js
├── domxss-assist.js
├── poc-trigger.js
├── ai-service.js
├── finger.json
├── kscan_fingerprint.json
├── webapp.json
├── apps.json
└── snow_x25.js
```

### 核心模块说明

- `background.js`
  - 背景页主入口
  - 负责消息分发、指纹汇总、报告存储、AI/PoC/Console 助手服务接入

- `content.js`
  - 页面扫描主入口
  - 负责前端信息收集、JS 拉取、DOMXSS 检测、报告上报

- `fingerprint-core.js`
  - 统一指纹引擎
  - content/background 共用

- `report-schema-core.js`
  - 报告字段与规范的单一来源

- `report-store.js`
  - 漏洞报告读写、合并、去重、删除

- `domxss-assist.js`
  - DOMXSS Console 动态验证助手

- `poc-trigger.js`
  - 主动注入与一键复现逻辑

- `ai-service.js`
  - AI 误报研判与会话能力

- `popup.js`
  - 前端工作台入口，负责 scanner/report/fingerprint/analysis/debug/config 全部页面交互

## 5. 当前技术特点

### 5.1 运行形态

- 纯浏览器扩展（Manifest V3）
- 无独立后端依赖即可运行基础能力
- 支持可选远程 AI Provider
- 当前代码直接以源码形式加载，无额外构建步骤

### 5.2 数据流

整体数据流大致为：

1. `content.js` 在页面侧进行扫描与 DOMXSS 检测
2. 指纹识别通过 `fingerprint-core.js` 在 content/background 共享运行
3. 漏洞报告经 `report-schema-core.js` 规范化后进入 `report-store.js`
4. `popup.js` 展示扫描结果、指纹结果和漏洞报告
5. 用户可在报告详情里继续走 Console 助手 / PoC / AI 研判流程

### 5.3 指纹引擎特点

- 多来源规则融合
- 多信号识别
- 统一评分
- 指纹去重
- 误报压制
- Wappalyzer 能力融合
- 外部大库缓存

## 6. 当前相对 v0.3.0 的结论

如果把 `SnowEyes v0.3.0` 看作一个“前端资产发现工具”，那么 `SnowEyesPlus` 已经是一个“前端安全审计工作流平台”。

它的变化不只是新增了几个功能按钮，而是发生了以下层面的升级：

- 从单体脚本升级为模块化架构
- 从静态结果展示升级为完整报告流转
- 从基础指纹匹配升级为统一指纹引擎
- 从发现问题升级为验证问题、复现问题、分析问题
- 从“可用”升级为“可维护、可扩展、可持续演进”

---

如果你是从 `SnowEyes v0.3.0` 迁移过来，可以直接把 `SnowEyesPlus` 理解为：

> 在保留原始信息搜集、指纹嗅探、网站解析能力的基础上，补齐 DOMXSS 检测、漏洞报告、验证复现、AI 研判、调试排障，并完成一轮架构重构的增强版。
