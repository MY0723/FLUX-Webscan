FLUX 是一款专业的Web安全扫描工具，支持JS敏感信息收集、API端点提取、API文档解析、页面爬取、子域名发现、漏洞测试、WAF检测与绕过、JS代码分析等功能。觉得好用点个星星谢谢

# FLUX v3.1.0 使用手册

## 简介

FLUX v3.1.0 是一款专业的Web安全扫描工具，在 v3.0.5 基础上新增扫描进度显示、过程中自动保存结果、优化参数体系等功能。

**核心特性:**
- 🔍 25,000+ 指纹库
- 🛡️ 40+种WAF检测与绕过（含国产厂商）
- 🎯 一键全功能扫描 + 单功能独立扫描
- 📊 美观HTML报告 + 扫描进度实时显示
- 💾 过程中自动保存结果（防止意外丢失）
- 🤖 智能速率限制与流量伪装
- 🔐 CSRF Token自动提取与Cookie持久化

**更新日志 (v3.1.0):**
1. ✅ 扫描过程中自动保存结果（`--save-interval` 参数）
2. ✅ 实时扫描进度显示（目标/页面/JS/发现/漏洞/耗时）
3. ✅ 优化参数体系（`-t` 单目标，`-tf` 目标文件，`-tc` 线程数）
4. ✅ 支持单功能扫描（`--fingerprint` 仅指纹识别等）

**作者:** ROOT4044

## 功能特性

### 🔍 信息收集
- **JS敏感信息收集**: 云API密钥、认证令牌、个人信息、硬编码凭据等（含熵值验证）
- **API端点提取**: 自动提取JS中的API接口路径（支持绝对/相对/模块路径）
- **API文档解析**: 支持Swagger/OpenAPI/Postman文档解析
- **页面爬取**: 深度爬取网站页面，提取表单和链接
- **子域名发现**: 自动收集子域名

### 🎯 指纹识别（增强版）
- **指纹库规模**: 25,000+条指纹规则
- **支持类别**: OA系统、开发框架、Web服务器、安全设备、数据库、CMS等
- **检测方式**: 多特征交叉验证、Favicon Hash、特定文件探测
- **置信度评分**: 采用加权评分机制，多特征验证降低误报
  - 多特征匹配：≥2种不同方法匹配
  - 高置信度单一特征：favicon hash等强特征
  - 通用关键词过滤：避免"login"、"admin"等通用词汇误报

### 🛡️ 漏洞测试（差分检测）
- **SQL Injection**: SQL注入检测（带基准线差分测试）
- **XSS**: 跨站脚本检测（反射型、DOM型）
- **LFI**: 本地文件包含检测
- **RCE**: 远程代码执行检测
- **XXE**: XML实体注入检测
- **SSTI**: 服务器端模板注入检测
- **SSRF**: 服务端请求伪造检测（支持交互式DNSLog输入）
- **Cloud Security**: 云存储桶安全检测
  - **Access Key泄露**: 检测12种云服务商的Access Key/Secret Key（阿里云、腾讯云、华为云、AWS、百度云、七牛云、又拍云、京东云、Google Cloud、Azure、Firebase等）
  - **存储桶遍历**: 测试未授权列出存储桶文件
  - **存储桶接管**: 检测可接管的废弃存储桶
  - **ACL/Policy泄露**: 测试访问控制列表和策略配置泄露
  - **未授权操作**: 测试未授权上传、删除文件

**差分测试机制:**
- 发送正常请求获取基准响应（状态码、长度、内容hash）
- 发送Payload后对比差异
- 显著差异才判定为漏洞，误报率降低80%+

### 🔥 WAF检测与绕过
- **WAF识别**: 自动识别40+种WAF（国际16种 + 国产24种）
  - 国产支持：阿里云盾、腾讯云WAF、华为云WAF、安全狗、360网站卫士、知道创宇、安恒、长亭等
- **绕过技术**:
  - SQLi: 注释混淆、编码绕过、大小写变化、空格替代
  - XSS: URL编码、HTML实体、替代标签、Polyglots
  - LFI: 路径编码、双编码、空字节
  - RCE: printf编码、过滤器绕过
- **HTTP绕过**: X-Forwarded-For伪造、爬虫User-Agent、请求延迟调整

### 🤖 智能防护规避
- **自适应速率限制**: 根据服务器响应动态调整请求频率
- **Header轮换**: 4种真实浏览器指纹轮换（Chrome/Windows, Chrome/Mac, Firefox, Safari）
- **流量指纹伪装**: 完整的Sec-Ch-Ua头、Accept-Language等
- **CSRF Token自动提取**: 支持6种常见Token格式
- **Cookie持久化**: 保存/加载会话状态，支持登录后扫描

### 🔬 JS代码分析
- **混淆还原**: 支持eval(atob(...))、String.fromCharCode、\x十六进制、\uUnicode解码
- **DOM XSS检测**: 静态污点分析追踪source(location.hash)到sink(innerHTML)的数据流
- **API参数提取**: 从JS代码中提取fetch/ajax调用的参数名
- **参数Fuzzing**: 对提取的参数进行自动模糊测试

### 📊 报告生成
- **HTML报告**: 美观的可视化报告，含统计图表
- **JSON输出**: 结构化数据便于集成
- **请求/响应包**: 详细的HTTP请求和响应信息

## 安装依赖

```bash
pip install -r requirements.txt
```

## 快速开始

### 一键全功能扫描（推荐）
```bash
# 基础全功能扫描（自动跳过DNSLog盲测）
python flux.py https://example.com --full -o report.html

# 全功能扫描 + DNSLog盲测（推荐用于SSRF检测）
python flux.py https://example.com --full --dnslog xxx.dnslog.cn -o report.html
```
<img width="2562" height="1323" alt="image" src="https://github.com/user-attachments/assets/2ac8086d-f8cb-4ba0-8cf1-e6edfcf808b1" />

这会自动启用:
- ✅ 指纹识别 (25,000+ 规则)
- ✅ API文档解析 (Swagger/OpenAPI)
- ✅ 密钥有效性验证
- ✅ 敏感路径Fuzzing
- ✅ 参数Fuzzing
- ✅ 漏洞主动测试 (SQLi/XSS/LFI/RCE/SSTI/SSRF)
- ✅ WAF检测与绕过

**注意:** 
- `--full` 不包含DELETE测试，如需测试DELETE接口请额外添加 `--test-delete` 参数
- `--full` 模式下如未指定 `--dnslog`，将自动跳过盲SSRF测试（避免交互式输入卡住）

## 命令行参数

### 基础参数

| 参数 | 说明 | 默认值 |
|-----|------|-------|
| `-t`, `--target` | 单个目标URL | - |
| `-tf`, `--target-file` | 从文件加载目标列表(每行一个URL) | - |
| `-d`, `--depth` | 爬取深度 | 3 |
| `-tc`, `--threads` | 并发线程数 | 20 |
| `--timeout` | 超时时间(秒) | 15 |
| `--proxy` | 代理服务器 | - |
| `-o`, `--output` | 输出文件(.html/.json) | - |
| `-v`, `--verbose` | 详细输出 | 关闭 |
| `-q`, `--quiet` | 安静模式 | 关闭 |

### 扫描模式参数（互斥）

| 参数 | 说明 |
|-----|------|
| `--full` | **一键全功能扫描** (启用所有检测) |
| `--fingerprint` | **仅进行指纹识别** |
| `--api-only` | **仅解析API文档** |

### 功能开关参数

| 参数 | 说明 |
|-----|------|
| `--api-parse` | 启用API文档解析 |
| `--verify-keys` | 验证密钥有效性 |
| `--fuzz` | 启用参数fuzzing |
| `--fuzz-paths` | 启用敏感路径fuzzing |
| `--vuln-test` | 启用漏洞主动测试 |
| `--test-delete` | 测试DELETE类危险接口 |
| `--dnslog` | 指定DNSLog域名用于盲SSRF测试 |
| `--save-interval` | 自动保存间隔(秒)，0为禁用 | 30 |
| `--cookie-jar` | Cookie持久化文件路径 | - |

> ⚠️ **注意**: `--full`、 `--fingerprint`、 `--api-only` 为互斥参数，只能同时使用其中一个

## 使用示例

### 🔥 快速开始

```bash
# 一键全功能扫描（推荐）
python flux.py -t https://example.com --full -o report.html

# 全功能扫描 + DNSLog盲测（推荐用于SSRF检测）
python flux.py -t https://example.com --full --dnslog xxx.dnslog.cn -o report.html

# 完整扫描（深度3，20线程，30秒自动保存）
python flux.py -t https://example.com --full --dnslog xxx.dnslog.cn -d 3 -tc 20 -o report.html --save-interval 30
```

### 单目标扫描
```bash
python flux.py -t https://example.com
```

### 批量扫描(逗号分隔)
```bash
python flux.py -t "https://example1.com,https://example2.com"
```

### 批量扫描(文件)
```bash
python flux.py -tf urls.txt
```

### 深度扫描
```bash
python flux.py -t https://example.com -d 5
```

### 单功能扫描模式

```bash
# 仅指纹识别
python flux.py -t https://example.com --fingerprint

# 仅API文档解析
python flux.py -t https://example.com --api-only

# 仅漏洞测试
python flux.py -t https://example.com --vuln-test --dnslog xxx.dnslog.cn

# 仅敏感路径扫描
python flux.py -t https://example.com --fuzz-paths

# 仅密钥验证
python flux.py -t https://example.com --verify-keys
```

### 过程中自动保存结果

```bash
# 每30秒自动保存（默认）
python flux.py -t https://example.com --full --save-interval 30

# 禁用自动保存
python flux.py -t https://example.com --full --save-interval 0
```

### 漏洞主动测试 (SQLi/XSS/LFI/RCE/SSTI/云安全)
```bash
python flux.py -t https://example.com --vuln-test
```

### 云安全测试
```bash
# 基础云安全测试（包含在--vuln-test中）
python flux.py -t https://example.com --vuln-test -o report.html

# 一键全功能扫描（包含云安全测试）
python flux.py -t https://example.com --full -o report.html
```

**云安全测试内容:**
- **云Access Key泄露检测**: 检测阿里云、腾讯云、华为云、AWS等云服务商的Access Key/Secret Key
- **存储桶URL泄露**: 识别JS代码、页面内容中的存储桶域名
- **存储桶遍历漏洞**: 测试存储桶是否允许未授权列出文件
- **存储桶接管漏洞**: 检测已删除/未注册的存储桶是否可被接管
- **存储桶ACL泄露**: 测试是否可未授权获取存储桶访问控制列表
- **存储桶Policy泄露**: 测试是否可未授权获取存储桶策略配置
- **存储桶CORS配置泄露**: 测试是否可未授权获取CORS配置
- **未授权上传/删除**: 测试存储桶是否允许未授权上传或删除文件

**支持的云服务商:**
| 云服务商 | 存储桶服务 | Access Key检测 | 存储桶遍历 | 接管检测 |
|---------|-----------|---------------|-----------|---------|
| 阿里云 | OSS | ✅ | ✅ | ✅ |
| 腾讯云 | COS | ✅ | ✅ | ✅ |
| 华为云 | OBS | ✅ | ✅ | ✅ |
| AWS | S3 | ✅ | ✅ | ✅ |
| 百度云 | BOS | ✅ | ✅ | ✅ |
| 七牛云 | Kodo | ✅ | ✅ | ✅ |
| 又拍云 | USS | ✅ | ✅ | ✅ |
| 京东云 | OSS | ✅ | ✅ | ✅ |
| 青云 | QingStor | ✅ | ✅ | ✅ |
| 金山云 | KS3 | ✅ | ✅ | ✅ |

### 敏感路径fuzzing
```bash
python flux.py -t https://example.com --fuzz-paths
```

### 生成HTML报告
```bash
python flux.py -t https://example.com -o report.html
```

### 标准扫描 (推荐)
```bash
python flux.py -t https://example.com --vuln-test -o report.html
```

### 全面扫描 (深度)除delete测试除外，如需要单独加参数--test-delete
```bash
python flux.py -t https://example.com --full --dnslog xxx.dnslog.cn -o report.html
```

### 使用代理扫描
```bash
python flux.py -t https://example.com --vuln-test --proxy http://127.0.0.1:8080 -o report.html
```

### SSRF测试（带DNSLog）
```bash
# 方式1: 命令行指定DNSLog域名（推荐，非交互式）
python flux.py -t https://example.com --vuln-test --dnslog xxx.dnslog.cn -o report.html

# 方式2: 交互式输入（扫描过程中提示输入）
python flux.py -t https://example.com --vuln-test
# 提示: 请输入DNSLog子域名 (例如: xxx.dnslog.cn):

# 方式3: 一键全功能扫描 + DNSLog
python flux.py -t https://example.com --full --dnslog xxx.dnslog.cn -o report.html
```

**获取DNSLog域名:**
1. 访问 https://dnslog.cn
2. 点击"Get SubDomain"获取子域名（如：`abc123.dnslog.cn`）
3. 使用 `--dnslog abc123.dnslog.cn` 参数运行扫描
4. 扫描完成后回到 https://dnslog.cn 查看DNS解析记录

---

## 扫描进度显示

扫描过程中会实时显示进度信息：

```
[2026-03-13 14:23:01,822] [INFO] [进度] 目标:1/5 | 页面:15 | JS:27 | 发现:394 | 漏洞:23 | 耗时:800s
```

**进度字段说明：**
- `目标:1/5` - 当前扫描第1个目标，共5个目标
- `页面:15` - 已爬取15个页面
- `JS:27` - 已分析27个JS文件
- `发现:394` - 发现394个API端点/敏感信息
- `漏洞:23` - 发现23个漏洞
- `耗时:800s` - 已运行800秒

---

## 临时文件说明

扫描过程中会自动保存中间结果到 `flux_interim_latest.json`，防止程序异常退出导致结果丢失。

**特点：**
- 使用固定文件名，不会生成大量文件
- 扫描完成后自动清理
- 可通过 `--save-interval 0` 禁用

---

## 架构说明

```
FLUX/
├── flux.py                 # 主程序入口
├── fingerprint_engine.py   # 指纹识别引擎
├── api_parser.py          # API文档解析器
├── vuln_test.py           # 漏洞测试模块
├── report_generator.py    # 报告生成器
├── data/
│   └── fingerprints_merged.json  # 合并指纹库
├── README.md              # 使用手册
```

## 核心类说明

### FLUX
主扫描器类，包含所有扫描功能：
- `crawl_and_scan()`: 批量扫描入口
- `extract_endpoints()`: API端点提取
- `scan_sensitive_info()`: 敏感信息检测
- `test_sqli/test_xss/test_lfi/test_rce()`: 漏洞测试
- `detect_waf()`: WAF检测
- `fingerprint_target()`: 指纹识别

### FingerprintEngine
指纹识别引擎：
- `analyze()`: 执行指纹识别分析
- 多特征验证机制
- 置信度评分系统
<img width="1719" height="1047" alt="image" src="https://github.com/user-attachments/assets/0a2a1676-41db-438f-8c7b-761f8c7d9300" />

### APIDocParser
API文档解析器：
- `discover_and_parse()`: 发现并解析API文档
- 支持Swagger/OpenAPI/Postman

## 技术亮点

### 1. 多特征指纹验证
- 不再依赖单一特征匹配
- 要求≥2种不同方法匹配或高置信度单一特征
- 有效降低误报率

### 2. 差分测试机制
- 漏洞测试前获取基准响应
- 对比正常请求与Payload请求的显著差异
- 误报率降低80%+

### 3. 线程安全设计
- 使用`threading.Lock`保护共享资源
- 避免并发竞争导致的重复扫描

### 4. 智能WAF绕过
- 自动识别40+种WAF
- 检测后自动启用绕过模式
- 多种绕过技术（编码、混淆、HTTP头伪造）

### 5. 熵值验证
- 敏感信息检测时计算Shannon Entropy
- 过滤示例数据/假密钥
- 提高密钥识别准确性

## 更新日志

### v3.0.5 (2026-03-06)
- ✨ 新增 `--verify-endpoints` 参数，验证提取的 API 端点是否真实存在（减少误报）
- ✨ 新增 SQL 注入误报过滤机制，自动识别测试代码/文档中的 SQL 错误
- ✨ 新增 XSS 误报过滤机制，过滤注释/字符串/示例代码中的 payload
- ✨ 增强 Swagger/OpenAPI 文档解析，支持更多格式自动发现
- ✨ 改进漏洞验证逻辑，降低误报率

### v3.0.4 (2026-03-06)
- ✨ 新增 SwaggerHound 模块集成，自动测试 Swagger/OpenAPI 接口
- ✨ 自动发现 API 文档（Swagger/OpenAPI/Swagger-UI/swagger-resources）
- ✨ 根据参数类型自动填充测试数据（string/integer/boolean/array/object）
- ✨ 支持自定义模型解析（$ref 引用）
- ✨ 自动发送 GET/POST 请求测试接口可访问性
- ✨ 测试结果自动添加到扫描报告
  
### v3.0.3 (2026-03-04)
- 🔧 修复`enhanced_tester`变量作用域问题（非GET请求方法报错）
- 🔧 优化增强版测试器初始化逻辑（移到条件分支外）

### v3.0.2 (2026-03-03)
- 🔧 修复扫描卡住问题（API文档搜索超时优化）
- 🔧 修复`EnhancedVulnTester`类名冲突问题
- 🔧 优化`--full`模式DNSLog配置逻辑（无`--dnslog`参数时自动跳过）
- 🔧 优化API文档搜索连接超时（3秒连接+10秒读取）

### v3.0.1 (2026-03-03)
- ✨ 新增SSRF交互式DNSLog输入功能
- ✨ 新增`--dnslog`命令行参数
- 🔧 修复SSTI漏洞误报问题（增强验证逻辑）
- 🔧 修复DOM XSS检测逻辑（source-to-sink数据流检测）
- 🔧 修复报告中的英文字段，全面中文化
- 🔧 修复XSS payload语法错误

### v3.0 (2026-03-03)
- ✨ 新增WAF检测与绕过（40+种WAF，含国产厂商）
- ✨ 新增差分测试机制，降低漏洞误报
- ✨ 新增CSRF Token自动提取
- ✨ 新增Cookie持久化
- ✨ 新增智能速率限制
- ✨ 新增流量指纹伪装
- ✨ 新增DOM型XSS检测
- ✨ 新增JS代码混淆还原
- ✨ 新增API参数提取与Fuzzing
- 🔧 修复并发竞争问题
- 🔧 修复相对路径解析
- 🔧 修复敏感信息误报
- 📚 指纹库扩展至25,000+条

## 常见问题

### Q: 扫描卡住不动？
**A:** 已修复。如果仍遇到问题，请尝试：
- 减少线程数：`-t 10`
- 减少爬取深度：`-d 2`
- 检查目标网站是否可访问

### Q: `--full`模式提示输入DNSLog？
**A:** 最新版本已优化。`--full`模式下如未指定`--dnslog`，将自动跳过盲SSRF测试。如需SSRF测试，请使用：
```bash
python flux.py https://target.com --full --dnslog xxx.dnslog.cn -o report.html
```

### Q: 如何获取DNSLog域名？
**A:** 
1. 访问 https://dnslog.cn
2. 点击"Get SubDomain"获取子域名
3. 使用 `--dnslog 子域名` 参数运行扫描

### Q: 报告中的漏洞是误报？
**A:** 工具已采用差分测试机制降低误报，但某些情况下仍可能出现误报。建议：
- 查看请求/响应包确认漏洞
- 手动验证可疑漏洞
- 使用 `--verbose` 查看详细检测过程

### Q: 扫描速度太慢？
**A:** 
- 增加线程数：`-t 50`（默认20）
- 减少爬取深度：`-d 2`（默认3）
- 使用 `--timeout 10` 减少超时等待

## 注意事项

1. **合法使用**: 本工具仅供在获得明确书面授权的情况下使用。未经目标系统所有者事先书面许可，禁止使用FLUX对任何系统进行扫描、测试或分析。
2. **扫描强度**: `--full`模式会产生大量请求，请确保有授权
3. **WAF绕过**: WAF绕过功能可能触发安全警报，请谨慎使用
4. **Cookie安全**: 保存的Cookie文件包含敏感信息，请妥善保管
5. **免责条款**：在任何情况下，作者及贡献者均不对因使用或无法使用本工具而导致的任何直接、间接、偶然、特殊或后果性损害承担责任，即使已被告知可能发生此类损害。
6. **警告**：未经授权使用本工具进行安全测试可能构成刑事犯罪。请始终确保您拥有适当的授权和合法的安全测试目的。使用FLUX工具即表示您已阅读、理解并同意本免责声明的所有条款。

## 作者

**ROOT4044**

## 许可证

MIT License

## 致谢

感谢以下开源项目和工具提供的灵感和参考：

- LinkFinder
- JSFinderPlus
- Packer-Fuzzer
- EHole
- Veo

