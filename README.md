FLUX v3.0 是一款专业的Web安全扫描工具，JS敏感信息收集、API端点提取、API文档解析、页面爬取、子域名发现、漏洞测试、WAF检测与绕过、JS代码分析等功能。

# FLUX v3.0 使用手册

## 简介

FLUX v3.0 是一款专业的Web安全扫描工具，新增完整规则库、美观HTML报告、可视化统计等功能。

**核心特性:**
- 🔍 25,000+ 指纹库
- 🛡️ 40+种WAF检测与绕过（含国产厂商）
- 🎯 一键全功能扫描
- 📊 美观HTML报告
- 🤖 智能速率限制与流量伪装
- 🔐 CSRF Token自动提取与Cookie持久化

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
pip install requests beautifulsoup4 colorlog pyyaml
```

## 快速开始

### 一键全功能扫描（推荐）
```bash
# 基础全功能扫描（自动跳过DNSLog盲测）
python flux.py https://example.com --full -o report.html

# 全功能扫描 + DNSLog盲测（推荐用于SSRF检测）
python flux.py https://example.com --full --dnslog xxx.dnslog.cn -o report.html
```

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

| 参数 | 说明 | 默认值 |
|-----|------|-------|
| `target` | 目标URL、URL列表(逗号分隔)、或URL文件路径 | 必填 |
| `-l`, `--list` | 从文件加载目标列表(每行一个URL) | - |
| `-d`, `--depth` | 爬取深度 | 3 |
| `-t`, `--threads` | 并发线程数 | 20 |
| `--timeout` | 超时时间(秒) | 15 |
| `--proxy` | 代理服务器 | - |
| `-o`, `--output` | 输出文件(.html/.json) | - |
| `--full` | **一键全功能扫描** (启用所有检测) | 关闭 |
| `--api-parse` | 启用API文档解析 | 关闭 |
| `--verify-keys` | 验证密钥有效性 | 关闭 |
| `--fuzz` | 启用参数fuzzing | 关闭 |
| `--fuzz-paths` | 启用敏感路径fuzzing | 关闭 |
| `--vuln-test` | 启用漏洞主动测试 | 关闭 |
| `--test-delete` | 测试DELETE类危险接口 | 关闭 |
| `--dnslog` | 指定DNSLog域名用于盲SSRF测试 | - |
| `-v`, `--verbose` | 详细输出 | 关闭 |
| `-q`, `--quiet` | 安静模式 | 关闭 |

## 使用示例

### 单目标扫描
```bash
python flux.py https://example.com
```

### 批量扫描(逗号分隔)
```bash
python flux.py "https://example1.com,https://example2.com"
```

### 批量扫描(文件)
```bash
python flux.py urls.txt
```

### 深度扫描
```bash
python flux.py https://example.com -d 5
```

### 漏洞主动测试 (SQLi/XSS/LFI/RCE/SSTI/云安全)
```bash
python flux.py https://example.com --vuln-test
```

### 敏感路径fuzzing
```bash
python flux.py https://example.com --fuzz-paths
```

### 生成HTML报告
```bash
python flux.py https://example.com -o report.html
```

### 标准扫描 (推荐)
```bash
python flux.py https://example.com --vuln-test -o report.html
```

### 全面扫描 (深度)除delete测试除外，如需要单独加参数--test-delete
```bash
python flux.py https://example.com --full --dnslog xxx.dnslog.cn -o report.html
```

### 使用代理扫描
```bash
python flux.py https://example.com --vuln-test --proxy http://127.0.0.1:8080 -o report.html
```

### SSRF测试（带DNSLog）
```bash
# 方式1: 命令行指定DNSLog域名（推荐，非交互式）
python flux.py https://example.com --vuln-test --dnslog xxx.dnslog.cn -o report.html

# 方式2: 交互式输入（扫描过程中提示输入）
python flux.py https://example.com --vuln-test
# 提示: 请输入DNSLog子域名 (例如: xxx.dnslog.cn):

# 方式3: 一键全功能扫描 + DNSLog
python flux.py https://example.com --full --dnslog xxx.dnslog.cn -o report.html
```

**获取DNSLog域名:**
1. 访问 https://dnslog.cn
2. 点击"Get SubDomain"获取子域名（如：`abc123.dnslog.cn`）
3. 使用 `--dnslog abc123.dnslog.cn` 参数运行扫描
4. 扫描完成后回到 https://dnslog.cn 查看DNS解析记录

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
