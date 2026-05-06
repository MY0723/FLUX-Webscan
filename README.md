<img width="410" height="200" alt="8113fb214fd3dba12c4a7532d46c951a" src="https://github.com/user-attachments/assets/b98185db-0f95-494b-bbe4-68b9c0482963" />


FLUX v5.4.5是一款专业的Web安全扫描工具，支持CLI和Web界面双模式运行。新增WAF指纹识别与智能Bypass引擎、700+通用Bypass Payload池、并发扫描优化、二进制文件过滤、Web界面图形化操作等功能，支持静态/渲染/混合三种扫描策略，集成Playwright实现SPA/前端路由页面扫描。本次更新重点修复云密钥检测误报问题，大幅降低字节跳动等云服务密钥的假阳性。

**作者:** ROOT4044
**版本:** v5.4.5
**更新日期:** 2026-04-21

# FLUX v5.4.5 使用手册

## 目录
- [简介](#简介)
- [功能特性](#功能特性)
- [安装依赖](#安装依赖)
- [Web界面模式](#web界面模式-v542-新增)
- [快速开始](#快速开始)
- [命令行参数](#命令行参数)
- [使用示例](#使用示例)
- [架构说明](#架构说明)
- [技术亮点](#技术亮点)
- [更新日志](#更新日志)
- [常见问题](#常见问题)
- [注意事项](#注意事项)
- [作者](#作者)
- [许可证](#许可证)
- [致谢](#致谢)

## 简介

FLUX v5.4.5是一款专业的Web安全扫描工具，支持CLI命令行和Web界面双模式运行。本次更新重点修复云密钥检测误报问题，包括字节跳动API Key、阿里云/腾讯云SecretKey、百度云AK、地图API密钥等通用字符模式的高假阳性问题。


**核心特性:**
- 🔍 25,156+ 指纹库 (含46个AI组件)
- 🛡️ **130+种WAF指纹识别** (融合wafw00f，覆盖云服务/国产/商业/开源)
- 💣 **700+通用Bypass Payload** (59类绕过技术，12大类SQLi/XSS/LFI/RCE/SSRF)
- 🎯 一键全功能扫描
- 📊 美观HTML报告 (含WAF识别独立Tab)
- 📄 实时JSON报告（每10秒自动保存）
- 🔄 fscan/dddd结果导入
- 🤖 智能速率限制与流量伪装
- 🔐 CSRF Token自动提取与Cookie持久化
- 💾 断点续扫增强（保存完整状态）
- 🛡️ 减少误报（隐藏文件/敏感路径过滤优化）
- 🌐 **静态/渲染/混合三种扫描模式**
- 🖥️ **浏览器渲染扫描（SPA/前端路由支持）**
- 📡 **运行时XHR/fetch请求捕获（含响应特征）**
- 🤝 **登录态/Cookie/Storage/Token会话贯通**
- 🖱️ **轻量交互引擎（智能评分点击）**
- 🕷️ **状态化动态Spider（BFS状态队列）**
- 🛤️ **前端路由追踪（pushState/hashchange）**
- 🔇 **结果降噪（第三方/埋点过滤）**

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

### 🤖 AI基础设施安全检测 (v4.2+)
- **AI推理服务 (5个)**: Ollama、vLLM、Xinference、Triton Inference Server、TGI
- **AI工作流平台 (5个)**: n8n、Dify、Flowise、LangFlow、ComfyUI
- **AI聊天界面 (4个)**: OpenWebUI、ChatGPT-Next-Web、LobeChat、Gradio
- **AI开发工具 (7个)**: Jupyter Notebook、JupyterLab、Jupyter Server、MLflow、Kubeflow、Ray、TensorBoard
- **AI数据平台 (3个)**: Feast、ClickHouse、Dask
- **国产AI平台 (6个)**: FastGPT、MaxKB、RAGFlow、QAnything、ChuanhuGPT、OneAPI
- **AI开发框架 (5个)**: LangChain、LangServe、LangFuse、LiteLLM、FastChat
- **其他AI工具 (6个)**: Stable Diffusion WebUI、LLaMA-Factory、AnythingLLM、Marimo、KubePi、MCP
- **CVE漏洞检测**: 589+ AI组件CVE (基于AI-Infra-Guard v3.6.2)
- **提示词注入检测**: 系统提示泄露、角色扮演绕过、分隔符绕过等
- **模型窃取检测**: 未授权模型列表获取
- **版本检测**: 自动提取组件版本并匹配CVE

### ☸️ Kubernetes安全检测 (v4.0+)
- **K8s组件检测**: API Server、Dashboard、etcd、kubelet、kube-proxy
- **未授权访问检测**: 各组件未授权访问测试
- **CVE漏洞扫描**: CVE-2018-1002102、CVE-2019-11247、CVE-2020-8554等
- **配置泄露检测**: 配置文件、密钥泄露

### 🐳 容器安全检测 (v4.0+)
- **容器逃逸风险**: 特权容器、危险挂载检测
- **Docker API**: 未授权访问检测
- **Containerd/CRI-O**: 运行时安全检测
- **容器CVE库**: CVE-2019-5736、CVE-2020-15257、CVE-2021-30465、CVE-2022-0847等

### 🔄 CI/CD配置安全检测 (v4.3+)
- **CI/CD配置文件泄露**: 
  - GitLab CI (.gitlab-ci.yml)
  - Jenkins (Jenkinsfile, credentials.xml)
  - GitHub Actions (.github/workflows/)
  - Travis CI, CircleCI, Drone CI, Azure Pipelines
  - Docker (Dockerfile, docker-compose.yml)
  - Kubernetes (deployment.yaml, secret.yaml)
  - Ansible, Terraform配置
- **敏感信息检测** (17种Token类型):
  - GitLab Token / Runner Token
  - Jenkins API Token
  - Travis CI / CircleCI Token
  - Docker Hub Token / Registry Auth
  - npm / PyPI / RubyGems Token
  - Slack / Discord Webhook
- **环境变量泄露检测**:
  - AWS Access Key / Secret Key
  - Database URL with password
  - Private Key in ENV
  - 密码/密钥在环境变量中

### ✅ 漏洞利用验证 (v4.1+)
- **自动验证**: 高危/严重漏洞自动验证
- **SQL注入验证**: 时间盲注、错误回显验证
- **RCE验证**: 延迟执行、输出回显验证
- **LFI验证**: 文件读取验证
- **SSRF验证**: 内部服务访问验证
- **云元数据验证**: 云实例元数据访问验证
- **AI/K8s/Docker验证**: 未授权访问验证
- **利用证明**: 生成PoC和影响评估

### 🔥 WAF指纹识别与智能Bypass (v5.4.1)
- **WAF识别**: 自动识别**130+种WAF**（融合wafw00f，多维度检测）
  - **云服务**: Cloudflare, AWS WAF, Azure Application Gateway, Google Cloud Armor, Akamai, Fastly等
  - **国产WAF**: 阿里云盾, 腾讯云WAF, 华为云WAF, 安全狗, 云锁, 360网站卫士, 长亭雷池, 知道创宇, 安恒等
  - **商业WAF**: F5 BIG-IP, Fortinet, Barracuda, Radware, Sophos, Wordfence, Wallarm等
  - **开源方案**: ModSecurity, NAXSI, Varnish, Coraza等
  - **WordPress插件**: Wordfence, Sucuri, iThemes Security, All In One WP Security等
- **检测维度**: 响应头 + 响应体 + Cookie 三维匹配，置信度评分排序
- **Bypass Payload引擎 (v5.4.1)**:
  - **11种专用绕过**: 每种主流WAF有针对性payload（SQLi/XSS/LFI/RCE/SSRF各5-8个）
  - **700+通用池**: 59类绕过技术（空白替换/大小写/双写/编码/宽字节/时间盲注/报错注入/堆叠查询/Null截断/伪协议/反弹Shell/云元数据/OOB外带...）
  - **无WAF也增强**: 即使未检测到WAF，通用增强payload也会参与测试（提高检测率）
- **智能策略选择**: 根据WAF类型自动选择HTTP头绕过（Cloudflare用Chrome UA、国产WAF用爬虫UA等）
- **报告集成**: 命令行实时输出 + HTML报告独立"WAF识别"Tab + 漏洞标注绕过来源

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
- **漏洞验证状态**: 标识已验证/未验证漏洞

### 🖥️ 浏览器渲染扫描 (v5.0+)
- **三种扫描模式**: static（静态）、render（渲染）、hybrid（混合）
- **Playwright集成**: 使用真实浏览器渲染SPA/前端路由页面
- **运行时请求捕获**: 捕获XHR/fetch请求，识别真实API接口
- **登录态支持**: 加载Cookie到浏览器上下文，支持登录后扫描
- **会话贯通**: 浏览器Cookie可同步回requests会话
- **状态化Spider (v1.1)**: BFS状态队列调度，URL+路由+交互链路+页面签名去重
- **前端路由追踪 (v1.1)**: 监听history.pushState/hashchange/popstate路由变化
- **运行时响应感知 (v1.1)**: 捕获XHR/fetch响应特征(status_code/content_type/response_hash)
- **存储状态同步 (v1.1)**: localStorage/sessionStorage/Token同步到后续请求
- **结果降噪 (v1.1)**: 过滤第三方请求、埋点分析、CDN静态资源

### 🖱️ 轻量交互引擎 (v5.0+)
- **可控点击**: 预算控制下的高价值元素点击（默认最多10次/页3次）
- **智能识别**: 自动识别导航菜单、Tab切换、折叠面板、下拉按钮等8类元素
- **风险评分**: 避开危险按钮（删除/支付/注销/重置/卸载等15类关键词）
- **高价值优先**: 优先点击login/admin/dashboard/upload/api/swagger/config/manage/console
- **交互发现**: 点击后提取新链接和运行时请求，自动触发隐藏内容

## 安装依赖

```bash
pip install requests beautifulsoup4 colorlog pyyaml flask
```

## 🌐 Web界面模式 (v5.4.2 新增)

FLUX提供完整的Web界面，支持图形化操作和实时扫描监控。

### 启动方式

```bash
# 方式1: 直接双击运行 (推荐)
flux_web.exe
```

### Web界面功能

| 功能 | 说明 |
|------|------|
| 🎯 **扫描管理** | 新建扫描、查看历史、停止扫描 |
| 📊 **实时监控** | 实时日志滚动、进度百分比、耗时统计 |
| 📁 **报告管理** | 查看报告、下载HTML/JSON、删除报告 |
| ⚙️ **参数设置** | 并发数、超时时间、爬取深度等配置 |
| 📋 **目标导入** | 批量导入URL列表 (TXT/JSON格式) |
| 🔒 **自动清理** | 24小时前日志自动清理 |

### 界面预览

<img width="2538" height="1299" alt="image" src="https://github.com/user-attachments/assets/c8e84b19-26d0-4cf4-b915-ef80fed40713" />

<img width="2544" height="1299" alt="image" src="https://github.com/user-attachments/assets/0c6155cd-da2e-4be2-bf1c-897abacfe052" />

## 快速开始

### 一键全功能扫描（推荐）
```bash
# 基础全功能扫描（静态模式，适合大多数网站）
flux.exe -t https://example.com --full -d 3 -T 20 -o report.html

# 全功能扫描 + DNSLog盲测（推荐用于SSRF检测）
flux.exe -t https://example.com --full --dnslog xxx.dnslog.cn -o report.html
```

### 深度全功能扫描（最全）
```bash
# 混合模式 + 浏览器渲染 + 深度Spider（适合SPA应用）
flux.exe -t https://example.com --full --dnslog xxx.dnslog.cn -o report.html --scan-mode hybrid --render-deep-spider --render-enable-interaction -d 5
```

这会自动启用:
- ✅ 指纹识别 (25,136+ 规则，含46个AI组件)
- ✅ API文档解析 (Swagger/OpenAPI/Postman)
- ✅ 密钥有效性验证 (12种云服务商)
- ✅ 敏感路径Fuzzing
- ✅ 参数Fuzzing (从JS提取API参数)
- ✅ 漏洞主动测试 (SQLi/XSS/LFI/RCE/SSTI/SSRF/XXE，带差分检测)
- ✅ AI基础设施安全检测 (46+组件, 589+CVE)
- ✅ Kubernetes安全检测 (K8s组件, CVE扫描)
- ✅ 容器安全检测 (Docker/K8s逃逸风险)
- ✅ CI/CD配置安全检测 (配置文件/敏感Token/环境变量)
- ✅ 云安全测试 (Bucket遍历/密钥泄露)
- ✅ WAF检测与绕过 (40+种WAF含国产厂商)
- ✅ 智能速率限制 (自适应请求频率)
- ✅ 流量指纹伪装 (Header轮换)
- ✅ **[v1.2] JS智能解析** (Webpack/Vite/Next.js打包文件识别与拼接)
- ✅ **[v1.2] 端点融合引擎** (多来源去重、分类、置信度评分)
- ✅ **[v1.2] 敏感信息智能匹配** (结构化规则+上下文判断+白名单降噪)
- ✅ **[v1.2] 漏洞优先级排序** (基于上下文和可利用性智能排序)

**【最全】模式额外启用:**
- ✅ **[v1.1] 浏览器渲染扫描** (Playwright支持，SPA/前端路由)
- ✅ **[v1.1] 运行时XHR/fetch请求捕获** (含响应特征)
- ✅ **[v1.1] 状态化动态Spider** (BFS状态队列探索)
- ✅ **[v1.1] 前端路由追踪** (pushState/hashchange监听)
- ✅ **[v1.1] 轻量交互引擎** (智能点击评分)
- ✅ **[v1.1] 存储状态同步** (localStorage/sessionStorage/Token)

**注意:** 
- `--full` 不包含DELETE测试，如需测试DELETE接口请额外添加 `--test-delete` 参数
- `--full` 模式下如未指定 `--dnslog`，将自动跳过盲SSRF测试（避免交互式输入卡住）
- `--full` 已包含AI/K8s/容器安全检测，无需额外参数

## 命令行参数

| 参数 | 说明 | 默认值 |
|-----|------|-------|
| `-t`, `--target` | 目标URL或URL列表(逗号分隔) | 必填 |
| `-tf`, `--target-file` | 从文件加载目标列表(每行一个URL) | - |
| `-d`, `--depth` | 爬取深度 | 3 |
| `-T`, `--threads` | HTTP并发连接数 | 20 |
| `--timeout` | 超时时间(秒) | 15 |
| `--proxy` | 代理服务器 | - |
| `-o`, `--output` | 输出文件(.html/.json) | - |
| `--fingerprint` | 仅进行指纹识别扫描 | 关闭 |
| `--full` | **一键全功能扫描** (启用所有检测) | 关闭 |
| `--api-parse` | 启用API文档解析 | 关闭 |
| `--verify-keys` | 验证密钥有效性 | 关闭 |
| `--fuzz` | 启用参数fuzzing | 关闭 |
| `--fuzz-paths` | 启用敏感路径fuzzing | 关闭 |
| `--vuln-test` | 启用漏洞主动测试 | 关闭 |
| `--test-delete` | 测试DELETE类危险接口 | 关闭 |
| `--unsafe-mode` | 禁用安全模式，允许测试PUT/PATCH等危险方法 | 关闭 |
| `--dnslog` | 指定DNSLog域名用于盲SSRF测试 | - |
| `--cookie-file` | Cookie文件路径 (用于登录后扫描) | - |
| `--save-cookies` | 保存Cookie到指定文件 | - |
| `--fscan` | 从fscan扫描结果文件导入目标 | - |
| `--dddd` | 从dddd扫描结果文件导入目标 | - |
| `--check-alive` | 导入fscan/dddd结果时进行web存活验证 | 关闭 |
| `--resume` | 从进度文件恢复扫描 | - |
| `-v`, `--verbose` | 详细输出 | 关闭 |
| `-q`, `--quiet` | 安静模式 | 关闭 |
| `--scan-mode` | 扫描模式: static/render/hybrid | static |
| `--render-timeout` | 渲染超时时间(秒) | 30 |
| `--render-max-pages` | 渲染最大页面数 | 20 |
| `--render-enable-interaction` | 启用轻量交互引擎 | 关闭 |
| `--render-deep-spider` | 启用深度状态化Spider | 关闭 |

## 使用示例

### 单目标扫描
```bash
flux.exe -t https://example.com
```

### 批量扫描(逗号分隔)
```bash
flux.exe -t "https://example1.com,https://example2.com"
```

### 批量扫描(文件)
```bash
flux.exe -tf urls.txt
```

### 深度扫描
```bash
flux.exe -t https://example.com -d 5
```

### 漏洞主动测试 (SQLi/XSS/LFI/RCE/SSTI/云安全)
```bash
flux.exe -t https://example.com --vuln-test
```

### 云安全测试
```bash
# 基础云安全测试（包含在--vuln-test中）
flux.exe -t https://example.com --vuln-test -o report.html

# 一键全功能扫描（包含云安全测试）
flux.exe -t https://example.com --full -o report.html
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
flux.exe -t https://example.com --fuzz-paths
```

### 生成HTML报告
```bash
flux.exe -t https://example.com -o report.html
```

### 标准扫描 (推荐)
```bash
flux.exe -t https://example.com --vuln-test -o report.html
```

### 全面扫描 (深度)除delete测试除外，如需要单独加参数--test-delete
```bash
flux.exe -t https://example.com --full --dnslog xxx.dnslog.cn -o report.html
```

### 使用代理扫描
```bash
flux.exe -t https://example.com --vuln-test --proxy http://127.0.0.1:8080 -o report.html
```

### 渲染扫描（SPA/前端路由站点）
```bash
# 渲染模式 - 使用浏览器渲染扫描
flux.exe -t https://example.com --scan-mode render -o report.html

# 混合模式 - 静态+渲染（自动判断是否需要渲染）
flux.exe -t https://example.com --scan-mode hybrid -o report.html

# 渲染+交互 - 启用轻量交互引擎点击高价值元素
flux.exe -t https://example.com --scan-mode hybrid --render-enable-interaction -o report.html

# 渲染+Cookie - 加载登录态进行扫描
flux.exe -t https://example.com --scan-mode hybrid --cookie-file cookies.json -o report.html
```

### 深度动态识别扫描
```bash
# 启用深度状态化Spider（推荐用于复杂SPA）
flux.exe -t https://example.com --scan-mode hybrid --render-deep-spider -o report.html

# 深度Spider + 存储同步（登录态站点）
flux.exe -t https://example.com --scan-mode hybrid --render-deep-spider --cookie-file cookies.json -o report.html
```

### SSRF测试（带DNSLog）
```bash
# 方式1: 命令行指定DNSLog域名（推荐，非交互式）
flux.exe -t https://example.com --vuln-test --dnslog xxx.dnslog.cn -o report.html

# 方式2: 交互式输入（扫描过程中提示输入）
flux.exe -t https://example.com --vuln-test
# 提示: 请输入DNSLog子域名 (例如: xxx.dnslog.cn):

# 方式3: 一键全功能扫描 + DNSLog
flux.exe -t https://example.com --full --dnslog xxx.dnslog.cn -o report.html
```

**获取DNSLog域名:**
1. 访问 https://dnslog.cn
2. 点击"Get SubDomain"获取子域名（如：`abc123.dnslog.cn`）
3. 使用 `--dnslog abc123.dnslog.cn` 参数运行扫描
4. 扫描完成后回到 https://dnslog.cn 查看DNS解析记录

## 架构说明

```
FLUX/
├── flux.exe                # 主程序入口(CLI)
├── flux_web.exe            # Web界面入口(Flask)
├── flux.ico               # 程序图标
├── requirements.txt        # Python依赖
├── core/                   # 核心模块
│   ├── models.py           # 数据模型
│   ├── url_utils.py        # URL工具
│   ├── page_classifier.py  # 页面分类器
│   ├── path_verifier.py    # 路径验证器
│   ├── js_extractor.py     # JS提取器
│   ├── render_scan.py      # 浏览器渲染扫描
│   ├── render_state.py     # 状态化Spider
│   ├── route_tracker.py    # 前端路由追踪
│   ├── runtime_capture.py  # 运行时捕获增强
│   └── pipeline.py         # 扫描流水线
├── modules/                # 安全检测模块
│   ├── ai/                 # AI安全检测
│   ├── cloud/              # 云安全检测
│   ├── cicd/               # CI/CD安全检测
│   ├── container/          # 容器安全检测
│   ├── kubernetes/         # K8s安全检测
│   └── vulnerability/      # 漏洞测试
├── utils/
│   └── report.py           # 报告生成
├── templates/               # Web模板
│   └── flux_web.html       # Web界面HTML
├── static/                  # Web静态资源
│   ├── css/flux_web.css   # 样式表
│   ├── js/flux_web.js     # JavaScript
│   └── images/             # 图片资源
├── data/
│   └── fingerprints_merged.json  # 指纹库
└── README.md              # 使用手册
```

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

**v5.4.5 (2026-04-21) 指纹优化与域名筛选增强版本:**
- 🔍 **指纹识别结果优化**: 限制为Top 10（按置信度排序），避免输出过多无关指纹，提高结果可读性
- ⚖️ **冲突仲裁机制**: 同类产品只保留最高置信度，避免同一个组件多个版本同时显示
- 🌐 **HTML报告域名筛选功能增强**: 
  - 支持按域名筛选敏感信息、API端点、漏洞、JS文件、页面等数据
  - 域名筛选栏显示当前域名统计（敏感信息/API/漏洞/JS/页面数量）
  - 支持显示全部域名汇总统计
  - 筛选功能覆盖所有数据表格（findingsTable/endpointsTable/vulnsTable/jsFilesTable等）
- 🎯 **Bypass Payload可自定义采样数量**: 通过`--bypass-limit`参数控制bypass payload采样数量（默认30个，范围10-100）
- 💾 **Payload加载器模块**: 从YAML配置文件加载漏洞测试payload，支持用户自定义payload
- 🔧 **漏洞表格域名筛选完善**: vulnsTable已添加到域名筛选函数，实现漏洞数据按域名筛选

<img width="1235" height="621" alt="ede345f4b5534bb5b1602d5b9adf995c" src="https://github.com/user-attachments/assets/9e677e7a-418b-4515-906a-12ee8d5983bb" />

<img width="2462" height="330" alt="055633aeb4994a87bfcdfe6fa76a487d" src="https://github.com/user-attachments/assets/f8529100-954b-40a1-a855-2dbccfa6aa90" />

**v5.4.4 (2026-04-18) 云密钥误报修复版本:**
- 🔧 **字节跳动API Key检测加强**: 熵值阈值从3.5提高到4.5，增加字符种类验证(必须同时包含大小写字母和数字)
- 🛡️ **云密钥局部上下文验证加强**: 关键词距离要求从200字符收紧到100字符，至少2个关键词必须在附近
- 📊 **地图API密钥熵值提高**: 从3.2提高到3.8，减少随机字符串误报
- 🎯 **通用字符模式密钥过滤增强**: 阿里云/腾讯云/百度云/AWS等SecretKey增加熵值验证(3.5)和上下文距离检查
- ✅ **_analyze_local_context函数重构**: 增加key_type参数传递，对不同类型密钥应用差异化熵值标准

**v5.4.3 (2026-04-18) 误报优化版本:**
- 🔧 **RCE请求/响应对应修复**: 修复单次命中时请求与响应对不上的问题，重新发送请求获取真实对应的请求/响应对
- 🎯 **XSS检测上下文验证加强**: 只有在`<script>`标签内、事件处理器内或危险标签属性内才报告Confirmed，HTML转义反射不报告
- 🛡️ **SQLI关键字收紧**: 移除宽泛关键字(warning/exception/notice/undefined/mysql/syntax error)，保留精准SQL错误特征
- 📊 **SQLI状态码/长度差分验证**: 必须满足状态码变化或长度显著变化(>100字节)或新错误关键字>=2，大幅降低误报
- 🌐 **漏洞表格域名筛选修复**: 将vulnsTable添加到域名筛选函数，实现漏洞数据按域名筛选

**v5.4.2 新增特性:**
- 🌐 **Web界面模式**: 完整的图形化界面，支持扫描管理、实时监控、报告管理、参数设置
- 🛡️ **异步渲染扫描修复**: 修复asyncio.run()嵌套事件循环问题，添加浏览器启动超时控制(30秒)
- ⚡ **并发性能优化**: 
  - 路径fuzzing: 200+路径并发50线程测试
  - 隐藏文件扫描: 100+文件并发50线程测试
  - JS文件分析: 并发20线程下载分析
- 🔧 **扫描稳定性增强**:
  - 二进制文件过滤: 跳过.apk/.exe/.zip等大型二进制文件(避免下载 APK卡住)
  - 队列去重优化: O(n)→O(1)，添加queue_urls set快速去重
  - 渲染扫描超时: 5分钟超时控制，防止无限等待
  - 浏览器启动超时: 30秒超时，失败自动降级
- 📊 **性能优化**:
  - 保存进度防抖: 30秒间隔，减少I/O阻塞
  - 首页请求去重: 复用_fetch_page_info()响应
  - 线程安全修复: 使用update()/extend()代替引用赋值
  - 重试机制: 指数退避(2^attempt)
- 🔍 **软404检测增强**: 关键词列表扩展到28个
- 🤖 **子域名记录**: 爬取时自动记录子域名到subdomains集合
- 📈 **domainStats显示补全**: 显示端点/敏感/漏洞/JS/页面统计

**v5.4.1 新增特性:**
- 🛡️ **WAF指纹识别模块**: 融合wafw00f能力，支持130+种WAF检测（Cloudflare/阿里云盾/腾讯云WAF/长亭雷池等）
- 💣 **700+通用Bypass Payload池**: SQL注入(122) + XSS(122) + LFI(129) + RCE(150) + SSRF(177)，覆盖59类绕过技术
- 🎯 **智能Payload选择引擎**: 有WAF时专用bypass(70%)+通用池(30%)；无WAF时通用增强(50%)+默认(50%)
- 🔧 **11种主流WAF专用绕过**: Cloudflare/阿里云盾/腾讯云/安全狗/云锁/360/ModSecurity/F5/AWS/Azure/Wordfence
- 📊 **报告智能标记**: WAF Bypass模式 vs Enhanced模式，绕过结果必定返回到报告中

### v5.4 (2026-03-29)
- 🔄 **统一敏感信息扫描入口**: scan_sensitive_all() 支持7种来源，106条规则全链路复用
- 📊 **SecretMatcher全量化**: 移除JS文件[:20]限制，独立于vuln_test运行
- 🎯 **优先级采样机制**: _priority_sample() 替代固定切片，按风险评分采样
- 🔒 **SSRF危险探测**: --ssrf-dangerous 参数，支持内网/云元数据/协议探测
- 🌐 **Header轮换**: 模拟不同浏览器访问，绕过指纹识别
- 🛡️ **CSRF被动分析**: 检测敏感端点缺少CSRF防护
- ⚡ **--full模式增强**: 混合扫描模式+浏览器交互+深度Spider+SSRF危险探测
- 🐛 **多目标日志修复**: 每个目标生成独立日志文件
- 🧹 **代码清理**: 删除scanner.py中3个死入口方法

### v5.2.4 (2026-03-28)
- 📊 **报告优化**: API端点表格增加响应长度列(B/KB/MB智能显示)
- 📋 **一键复制**: 所有来源列(敏感信息/JS文件/API端点/绝对路径/相对路径/模块路径/前端路由)添加一键复制去重URL功能
- 🐛 **批量扫描修复**: 修复批量扫描时每个目标统计为0的问题

### v5.2.3 (2026-03-27)
- 🔒 **安全检测修复**: 复核链路Timeout处理、CSRF/CORS检测分离、XSS/RCE上下文判断、SSRF分层检测、未授权/越权多会话对照
- 📊 **报告优化**: 动态类型筛选、置信度筛选修复、列宽优化、复制展开冲突修复、来源列不换行
- 🛡️ **扫描模式分层**: low_risk/dangerous模式，CSRF主动测试需显式开启
- 🔧 **文件上传/XXE检测增强**: 证据链验证、XML输入点识别
- 🔧 **SQL注入**: time_based完整实现
- 🔧 **深度爬虫修复**: 统一depth参数控制、静态资源/HTML页面分离、路由状态预算控制
- 🔧 **指纹引擎优化**: 提升阈值(0.60→0.70)、单点body需交叉验证、扩展通用词库、修复faviconhash冲突
- 🔧 **漏洞报告增强**: AI/CI/CD/Cloud扫描器添加HTTP请求/响应包记录
- 🔧 **路径fuzzing优化**: 添加全局超时保护(120秒)，防止长时间卡住
- 📝 **报告表单展示**: 新增表单Tab，支持点击跳转查看

### v5.2.2 (2026-03-23)
- ✨ **JS智能解析模块**: Webpack/Vite/Next.js/Nuxt.js打包文件智能识别与拼接，提升JS文件获取成功率
- ✨ **端点融合引擎**: 多来源端点去重、分类、置信度评分、证据链管理
- ✨ **敏感信息智能匹配**: 结构化规则+上下文判断+白名单降噪+置信度评分，降低误报率
- ✨ **AI语义增强模块**: 可选AI辅助分析JS文件用途和端点风险（支持OpenAI）
- ✨ **漏洞优先级排序**: 基于上下文/可利用性/影响面的智能排序，高价值漏洞优先展示
- 🔧 修复: PageType枚举JSON序列化问题
- 🔧 修复: 报告生成时PageType枚举处理
- 🔧 优化: 参数简化，核心参数外移至内部默认值

### v5.1 / v1.1 深度动态识别版 (2026-03-20)
- ✨ **状态化动态Spider**: BFS状态队列调度，URL+路由+交互链路+页面签名多维去重
- ✨ **运行时响应感知**: 捕获XHR/fetch响应特征(status_code/content_type/content_length/response_hash)
- ✨ **前端路由追踪**: 注入JS监听history.pushState/replaceState/popstate/hashchange
- ✨ **存储状态同步**: 提取localStorage/sessionStorage中的Token并同步到后续请求
- ✨ **智能点击评分**: 优先点击menu/nav/tab/accordion，自动避开delete/pay/logout等危险操作
- ✨ **结果降噪**: 过滤第三方域名请求、埋点分析(analytics/tracking)、CDN静态资源
- ✨ **响应辅助分类**: 基于JSON/XML/HTML响应特征自动识别API端点
- ✨ **预算控制**: 最大页面数/深度可控，防止无限递归
- ✨ **状态链路追踪**: 记录每个状态的来源页面和点击链路，形成发现证据链

### v5.0 (2026-03-20) - 渲染扫描与交互增强
- ✨ **新增浏览器渲染扫描模式**: 支持 static/render/hybrid 三种扫描模式
- ✨ **Playwright集成**: 使用真实浏览器渲染SPA/前端路由页面
- ✨ **运行时请求捕获**: 捕获XHR/fetch请求，识别真实API接口
- ✨ **轻量交互引擎**: 预算控制下的高价值元素点击，发现更多页面
- ✨ **Cookie/登录态贯通**: 支持加载Cookie到浏览器、同步回requests会话
- ✨ **CLI布尔开关修复**: 支持显式开启/关闭渲染相关功能
- 🔧 修复Cookie回写时机问题（在浏览器上下文关闭前导出）
- 🔧 修复运行时确认结果合并逻辑（静态+渲染结果正确合并）
- 🔧 修复requirements.txt依赖声明格式
- 🔧 修复跨域请求过滤逻辑（runtime请求同源检查）
- 🔧 修复RenderConfig参数不匹配问题
- 🔧 修复DiscoveredURL对象模型访问问题

### v4.3.0 (2026-03-04) - CI/CD配置安全检测
- ✨ **新增CI/CD配置安全检测模块**: 独立模块检测CI/CD配置文件泄露和敏感信息
- ✨ **支持11种CI/CD配置文件检测**: GitLab CI、Jenkins、GitHub Actions、Travis CI、CircleCI、Drone CI、Azure Pipelines、Docker、Kubernetes、Ansible、Terraform
- ✨ **新增17种敏感Token检测**: GitLab Token、Jenkins API Token、Docker Hub Token、npm Token、Slack/Discord Webhook等
- ✨ **新增5种环境变量泄露检测**: AWS Key、Database URL、Private Key、Password等
- 🔧 **优化美图云存储桶检测**: 完善ACL/Policy端点配置，支持美图云详细安全测试

### v4.2.0 (2026-03-04) - AI-Infra-Guard集成增强
- ✨ **集成AI-Infra-Guard指纹库**：参考腾讯AI-Infra-Guard v3.6.2，新增40+AI组件检测
- ✨ **大幅扩展CVE库**：新增100+AI组件CVE漏洞，覆盖Gradio、Dify、ComfyUI、vLLM、Xinference、Triton、Ray、LiteLLM、ChuanhuGPT等
- ✨ **新增AI组件**：
  - 推理服务：Xinference、Triton Inference Server
  - 工作流：LangFlow
  - 聊天界面：Gradio
  - 开发工具：JupyterLab、Jupyter Server、TensorBoard
  - 数据平台：Feast、ClickHouse、Dask
  - 国产平台：ChuanhuGPT
  - 其他：LangFuse、LiteLLM、LLaMA-Factory、Marimo、KubePi、MCP
- ✨ **增强版本检测**：支持从API响应中提取组件版本号
- ✨ **智能CVE匹配**：根据检测到的版本自动匹配CVE漏洞

### v4.1.0 (2026-03-04) - AI工作流平台+漏洞验证
- ✨ **新增AI工作流平台检测**：支持n8n、Dify、Flowise、LangChain、ChatGPT-Next-Web、LobeChat、OneAPI、FastGPT、MaxKB、RAGFlow、AnythingLLM、QAnything等12+工作流平台
- ✨ **新增漏洞利用验证模块**：支持SQL注入、RCE、LFI、SSRF、云元数据、AI/K8s/Docker未授权等漏洞的验证性利用
- ✨ **完善CVE漏洞库**：新增CVE-2024-2221 (n8n)、CVE-2024-2219 (Dify)、CVE-2024-2222 (Flowise)、CVE-2023-39968 (Jupyter)、CVE-2024-2223 (OneAPI)、CVE-2024-2224 (FastGPT)
- ✨ **智能漏洞验证**：自动对高危/严重漏洞进行验证，生成利用证明和影响评估

### v4.0.0 (2026-03-04) - 重大更新
- ✨ **新增AI基础设施安全检测**：支持Ollama、vLLM、ComfyUI、OpenWebUI、LangServe、FastChat、TGI、Stable Diffusion WebUI、Jupyter Notebook、MLflow等10+AI组件
- ✨ **新增Kubernetes安全检测**：支持API Server、Dashboard、etcd、kubelet、kube-proxy等组件的未授权访问和CVE漏洞检测
- ✨ **新增容器安全检测**：支持Docker、Containerd、CRI-O运行时的容器逃逸、特权容器、危险挂载检测
- ✨ **新增CVE漏洞库**：包含CVE-2019-5736、CVE-2020-15257、CVE-2021-30465、CVE-2022-0847、CVE-2022-0492等容器相关CVE
- ✨ **新增AI CVE漏洞库**：包含CVE-2024-37032 (Ollama)、CVE-2024-21514 (ComfyUI)等AI组件CVE
- ✨ **新增提示词注入检测**：支持系统提示泄露、角色扮演绕过、分隔符绕过等攻击向量
- ✨ **新增K8s CVE漏洞库**：包含CVE-2018-1002102、CVE-2019-11247、CVE-2020-8554等K8s CVE

### v4.2 (2026-03-05)
- ✨ 新增AI基础设施安全检测 (46+组件, 589+CVE)
- ✨ 新增Kubernetes安全检测 (K8s组件, CVE扫描)
- ✨ 新增容器安全检测 (Docker/K8s逃逸风险)
- ✨ 新增CI/CD配置安全检测 (17种Token类型)
- ✨ 新增云存储桶安全检测 (12种云服务商)
- ✨ 新增漏洞利用验证 (高危漏洞自动验证)
- 🔧 优化指纹库规模 (25,154条规则)
- 🔧 优化WAF检测 (40+种WAF含国产厂商)

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
flux.exe -t https://target.com --full --dnslog xxx.dnslog.cn -o report.html
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

### Q: 如何导入其他扫描工具结果？
**A:**
```bash
# 导入fscan结果
flux.exe --fscan fscan_result.txt

# 导入dddd结果
flux.exe --dddd dddd_result.txt
```

### Q: 如何使用Cookie登录后扫描？
**A:**
1. 浏览器登录后导出Cookie（JSON格式）
2. 使用 `--cookie-file` 加载
```bash
flux.exe -t https://example.com --full --cookie-file cookies.json
```

**Cookie文件格式 (JSON)**:
```json
[
    {"name": "SESSION", "value": "abc123", "domain": ".example.com"},
    {"name": "token", "value": "xyz789", "domain": ".example.com"}
]
```

### Q: 什么情况下需要 `--ssrf-dangerous`？
**A:** 会进行危险探测：
- 云元数据探测 (AWS 169.254.169.254)
- 内网地址探测
- 协议探测 (file://, dict://)

⚠️ 仅在授权测试中使用，可能对目标造成影响

## 架构说明

```
FLUX/
├── flux.py                 # 主程序入口
├── core/                   # 核心模块
│   ├── fingerprint.py      # 指纹识别 (25,156+规则)
│   ├── waf_fingerprint.py # WAF指纹识别 (130+种)
│   ├── render_scan.py     # 浏览器渲染扫描
│   ├── render_state.py    # 状态化Spider
│   ├── runtime_capture.py  # 运行时请求捕获
│   └── route_tracker.py   # 前端路由追踪
├── modules/                # 扫描模块
│   ├── vulnerability/      # 漏洞测试 (SQLi/XSS/LFI/RCE/SSRF)
│   ├── ai/               # AI安全检测
│   ├── cloud/            # 云安全检测
│   ├── cicd/            # CI/CD安全检测
│   ├── container/        # 容器安全检测
│   └── kubernetes/       # K8s安全检测
├── utils/                  # 工具模块
│   └── report.py         # 报告生成 (HTML含WAF识别Tab)
├── config/                 # 配置文件
│   └── rules.yaml        # 扫描规则
└── data/                   # 数据文件
    └── fingerprints_merged.json  # 指纹库
```

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
- 
## Star History

<a href="https://www.star-history.com/?repos=MY0723%2FFLUX-Webscan&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=MY0723/FLUX-Webscan&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=MY0723/FLUX-Webscan&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=MY0723/FLUX-Webscan&type=date&legend=top-left" />
 </picture>
</a>
