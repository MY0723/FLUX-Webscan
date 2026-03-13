#!/usr/bin/env python3
"""
HTML报告生成模块 v3.0
"""

import html
import re
import time
from typing import Dict, List, Any

try:
    from vuln_test import get_api_type
except ImportError:
    def get_api_type(url: str) -> str:
        
        url_lower = url.lower()
        api_map = {
            "login": "登录接口", "register": "注册接口", "auth": "认证接口",
            "token": "Token接口", "user": "用户管理", "admin": "管理员接口",
            "order": "订单管理", "pay": "支付接口", "upload": "文件上传",
            "delete": "删除操作", "config": "配置管理", "settings": "系统设置",
        }
        for kw, tp in api_map.items():
            if kw in url_lower:
                return tp
        return "通用接口"


TYPE_NAME_MAP = {
    "cloud_keys": "云API密钥",
    "map_keys": "地图API",
    "auth_tokens": "认证令牌",
    "personal_info": "个人信息",
    "internal_ips": "内网IP",
    "email": "邮箱",
    "phone": "电话",
    "backup_files": "备份文件",
    "vulnerable_library": "危险组件",
    "dom_xss": "DOM型XSS",
    "sourcemap_leak": "源码泄露",
    "hardcoded_creds": "硬编码凭据",
    "sensitive_path": "敏感路径",
    "jsonp": "JSONP",
    "cors": "CORS",
    "ssrf": "SSRF",
    "webpack": "Webpack打包信息",
    "webpack_sourcemap": "Webpack源码泄露",
    "webpack_api": "Webpack隐藏API",
    "webpack_secrets": "Webpack敏感信息",
    "webpack_endpoints": "Webpack通信接口",
}

SEVERITY_NAME_MAP = {
    "Critical": "严重",
    "High": "高危",
    "Medium": "中危",
    "Low": "低危",
}

VULN_TYPE_MAP = {
    "SQL Injection": "SQL注入",
    "SQL Injection (Boolean)": "SQL注入(布尔盲注)",
    "XSS": "XSS跨站",
    "LFI": "本地文件读取",
    "RCE": "远程代码执行",
    "XXE": "XML实体注入",
    "CORS": "CORS配置不当",
    "CSRF": "CSRF跨站请求伪造",
    "Unauthorized Access": "未授权访问",
    "Horizontal Privilege": "水平越权",
    "Vertical Privilege": "垂直越权",
    "Sensitive Info Leak": "敏感信息泄露",
    "File Upload": "任意文件上传",
    "Weak Password": "弱口令",
    "JSONP": "JSONP泄露",
    "SSRF": "服务端请求伪造",
    "DOM XSS": "DOM型XSS",
}


def generate_html_report_v3(
    targets: List[str],
    results: List[Any],
    endpoints: List[Any],
    subdomains: List[str] = None,
    vuln_findings: List[Any] = None,
    output_file: str = None,
    scan_stats: Dict = None,
    js_files_list: List[Any] = None,
    pages_list: List[Any] = None,
    fingerprint_results: List[Any] = None,
    api_docs: List[Any] = None
) -> str:
    
    scan_stats = scan_stats or {}
    pages_count = scan_stats.get('pages', 0)
    forms_count = scan_stats.get('forms', 0)
    js_files_count = scan_stats.get('js_files', 0)
    js_files_list = js_files_list or []
    pages_list = pages_list or []
    
    absolute_apis_count = scan_stats.get('absolute_apis', 0)
    relative_apis_count = scan_stats.get('relative_apis', 0)
    module_paths_count = scan_stats.get('module_paths', 0)
    frontend_routes_count = scan_stats.get('frontend_routes', 0)
    
    critical = [r for r in results if r.severity == "Critical"]
    high = [r for r in results if r.severity == "High"]
    medium = [r for r in results if r.severity == "Medium"]
    low = [r for r in results if r.severity == "Low"]
    
    vuln_critical = []
    vuln_high = []
    vuln_medium = []
    vuln_low = []
    if vuln_findings:
        vuln_critical = [v for v in vuln_findings if v.severity == "Critical"]
        vuln_high = [v for v in vuln_findings if v.severity == "High"]
        vuln_medium = [v for v in vuln_findings if v.severity == "Medium"]
        vuln_low = [v for v in vuln_findings if v.severity == "Low"]
    
    # 按HTTP方法分类端点
    endpoints_get = [e for e in endpoints if e.method.upper() == "GET"]
    endpoints_post = [e for e in endpoints if e.method.upper() == "POST"]
    endpoints_put = [e for e in endpoints if e.method.upper() == "PUT"]
    endpoints_delete = [e for e in endpoints if e.method.upper() == "DELETE"]
    endpoints_patch = [e for e in endpoints if e.method.upper() == "PATCH"]
    endpoints_options = [e for e in endpoints if e.method.upper() == "OPTIONS"]
    endpoints_head = [e for e in endpoints if e.method.upper() == "HEAD"]
    endpoints_trace = [e for e in endpoints if e.method.upper() == "TRACE"]
    endpoints_connect = [e for e in endpoints if e.method.upper() == "CONNECT"]
    endpoints_ws = [e for e in endpoints if e.method.upper() in ["WS", "WEBSOCKET"]]

    # 其他类型：IMPORT, BASE, STATIC, RELATIVE, LOADER, PLUGIN, ENTRY, API等
    endpoints_other = [e for e in endpoints if e.method.upper() not in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT", "WS", "WEBSOCKET"]]

    # 高危接口统计
    high_risk_endpoints = [e for e in endpoints if e.risk_level == "High"]
    delete_endpoints = [e for e in endpoints if getattr(e, 'is_delete', False) or e.method.upper() == "DELETE"]
    upload_endpoints = [e for e in endpoints if 'upload' in e.url.lower()]
    admin_endpoints = [e for e in endpoints if 'admin' in e.url.lower() or 'manage' in e.url.lower()]

    # 统计数量
    high_risk_count = len(high_risk_endpoints)
    delete_count = len(delete_endpoints)
    upload_count = len(upload_endpoints)
    admin_count = len(admin_endpoints)
    
    cloud_keys_count = len([r for r in results if r.type == "cloud_keys"])
    auth_tokens_count = len([r for r in results if r.type == "auth_tokens"])
    personal_info_count = len([r for r in results if r.type == "personal_info"])
    hardcoded_creds_count = len([r for r in results if r.type == "hardcoded_creds"])
    sensitive_path_count = len([r for r in results if r.type == "sensitive_paths"])
    dom_xss_count = len([r for r in results if r.type == "dom_xss"])
    ssrf_count = len([r for r in results if r.type == "ssrf"])
    
    severity_stats = {
        "critical": len(critical) + len(vuln_critical),
        "high": len(high) + len(vuln_high),
        "medium": len(medium) + len(vuln_medium),
        "low": len(low) + len(vuln_low)
    }
    
    target_list = "<br>".join([html.escape(t) for t in targets])
    
    return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FLUX 安全扫描报告</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {{
            --primary-color: #2563eb;
            --bg-body: #f8f9fa;
            --bg-card: #ffffff;
            --bg-secondary: #f3f4f6;
            --bg-hover: #f9fafb;
            --text-primary: #1f2937;
            --text-secondary: #6b7280;
            --border-color: #e5e7eb;
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #16a34a;
        }}
        
        body {{
            background: var(--bg-body);
            min-height: 100vh;
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }}
        
        .header {{
            background: var(--bg-card);
            border-bottom: 1px solid var(--border-color);
            padding: 1.5rem 0;
            margin-bottom: 1.5rem;
        }}
        
        .header h1 {{
            margin: 0;
            font-weight: 600;
            font-size: 1.5rem;
            color: var(--text-primary);
        }}
        
        .target-url {{
            background: #f3f4f6;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.875rem;
            word-break: break-all;
        }}
        
        .stat-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 0.5rem 0.25rem;
            text-align: center;
            min-height: 60px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }}

        .stat-number {{
            font-size: 1.25rem;
            font-weight: 600;
            line-height: 1.2;
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.7rem;
            margin-top: 0.15rem;
            line-height: 1.2;
        }}

        /* 请求方式横向布局 */
        .method-stats-container {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            align-items: center;
            justify-content: space-between;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 0.5rem;
            min-height: 60px;
            width: 100%;
        }}

        .method-stat {{
            display: flex;
            align-items: center;
            gap: 0.3rem;
            cursor: pointer;
            transition: transform 0.2s;
            padding: 0.2rem 0.4rem;
            flex: 1;
            justify-content: center;
            min-width: 4rem;
        }}

        .method-stat:hover {{
            transform: scale(1.05);
        }}

        .method-badge {{
            color: white;
            font-size: 0.65rem;
            font-weight: 600;
            padding: 0.15rem 0.4rem;
            border-radius: 3px;
            white-space: nowrap;
        }}

        .method-count {{
            font-size: 0.9rem;
            font-weight: 600;
            color: var(--text-primary);
        }}

        .api-method-row {{
            align-items: stretch;
        }}

        .api-method-row > div {{
            display: flex;
        }}

        .api-endpoint-card {{
            flex: 1;
            display: flex;
            flex-direction: column;
            justify-content: center;
            min-height: 100%;
        }}
        
        .critical .stat-number {{ color: var(--critical); }}
        .high .stat-number {{ color: var(--high); }}
        .medium .stat-number {{ color: var(--medium); }}
        .low .stat-number {{ color: var(--low); }}
        
        .section-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 1rem;
        }}
        
        .section-header {{
            background: #f9fafb;
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
        }}

        .section-title {{
            font-size: 1.1rem;
            font-weight: 600;
            margin: 0;
            color: var(--text-primary);
        }}

        .filter-bar {{
            padding: 0.75rem 1rem;
            background: #f9fafb;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
            align-items: center;
        }}

        .filter-bar select {{
            background: var(--bg-card);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
            padding: 0.4rem 0.75rem;
            border-radius: 4px;
            font-size: 0.85rem;
        }}

        .table-wrapper {{
            overflow-x: hidden;
            max-width: 100%;
            min-height: 200px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
            border: 1px solid var(--border-color);
        }}
        
        th, td {{
            padding: 0.6rem 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            border-right: 1px solid var(--border-color);
            font-size: 0.85rem;
            vertical-align: top;
        }}
        
        th:first-child, td:first-child {{
            width: 80px;
            text-align: center;
        }}
        
        th:nth-child(2), td:nth-child(2) {{
            width: auto;
            min-width: 300px;
        }}
        
        th {{ background-color: var(--bg-secondary); font-weight: 600; }}
        
        tr:hover {{ background-color: var(--bg-hover); }}

        .copyable {{
            white-space: nowrap;
            overflow-x: auto;
            overflow-y: hidden;
            max-width: 100%;
            display: block;
            cursor: pointer;
            padding: 0.2rem 0;
            scrollbar-width: thin;
            scrollbar-color: #ddd #f8f8f8;
        }}

        .copyable::-webkit-scrollbar {{
            height: 1px;
        }}

        .copyable::-webkit-scrollbar-track {{
            background: #f8f8f8;
            border-radius: 2px;
        }}

        .copyable::-webkit-scrollbar-thumb {{
            background: #ccc;
            border-radius: 2px;
        }}

        .copyable::-webkit-scrollbar-thumb:hover {{
            background: #bbb;
        }}

        .copyable::-webkit-scrollbar {{
            height: 1px;
        }}

        .copyable::-webkit-scrollbar-track {{
            background: #f8f8f8;
            border-radius: 2px;
        }}

        .copyable::-webkit-scrollbar-thumb {{
            background: #ccc;
            border-radius: 2px;
        }}

        .copyable::-webkit-scrollbar-thumb:hover {{
            background: #bbb;
        }}

        th {{
            background: #f9fafb;
            font-weight: 600;
            white-space: nowrap;
            color: var(--text-secondary);
        }}
        
        tr:hover td {{
            background: #f9fafb;
        }}

        .severity {{
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
        }}

        .severity.critical {{
            background: #fee2e2;
            color: #dc2626;
        }}

        .severity.high {{
            background: #ffedd5;
            color: #ea580c;
        }}

        .severity.medium {{
            background: #fef9c3;
            color: #ca8a04;
        }}

        .severity.low {{
            background: #dcfce7;
            color: #16a34a;
        }}

        .method {{
            padding: 0.15rem 0.4rem;
            border-radius: 3px;
            font-size: 0.7rem;
            font-weight: 600;
        }}

        .method.get {{ background: #dcfce7; color: #16a34a; }}
        .method.post {{ background: #dbeafe; color: #2563eb; }}
        .method.put {{ background: #fef9c3; color: #ca8a04; }}
        .method.delete {{ background: #fee2e2; color: #dc2626; }}

        .type-badge {{
            padding: 0.15rem 0.4rem;
            border-radius: 3px;
            font-size: 0.7rem;
            background: #e5e7eb;
            color: #4b5563;
        }}

        .copyable {{
            cursor: pointer;
            overflow-x: auto;
            white-space: nowrap;
            display: inline-block;
        }}

        .copyable::-webkit-scrollbar {{
            height: 1px;
        }}

        .copyable::-webkit-scrollbar-track {{
            background: #f8f8f8;
        }}

        .copyable::-webkit-scrollbar-thumb {{
            background: #ccc;
            border-radius: 2px;
        }}

        .copyable:hover {{
            background: #e5e7eb;
        }}

        .toast {{
            position: fixed;
            bottom: 2rem;
            left: 50%;
            transform: translateX(-50%) translateY(100px);
            background: #374151;
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 6px;
            font-size: 0.85rem;
            opacity: 0;
            transition: all 0.3s;
            z-index: 9999;
        }}

        .toast.show {{
            opacity: 1;
            transform: translateX(-50%) translateY(0);
        }}

        .tabs {{
            display: flex;
            border-bottom: 1px solid var(--border-color);
            background: var(--bg-card);
        }}

        .tab {{
            padding: 0.75rem 1rem;
            cursor: pointer;
            border: none;
            background: none;
            color: var(--text-secondary);
            border-bottom: 2px solid transparent;
            font-size: 0.9rem;
        }}

        .tab:hover {{
            color: var(--text-primary);
        }}

        .tab.active {{
            color: var(--primary-color);
            border-bottom-color: var(--primary-color);
        }}
        
        .tab-content {{
            display: none;
            padding: 1rem;
        }}
        
        .tab-content.active {{
            display: block;
        }}
        
        .subdomain-tag {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            margin: 0.25rem;
            background: rgba(79, 70, 229, 0.2);
            border-radius: 20px;
            font-size: 0.85rem;
        }}
        
        .vuln-detail {{
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}
        
        .delete-warning {{
            color: #DC2626;
            font-size: 0.8rem;
            font-weight: bold;
            background: #FEE2E2;
            padding: 2px 8px;
            border-radius: 4px;
            display: inline-block;
            margin-top: 4px;
        }}

        .high-risk-row {{
            background: #FEF2F2 !important;
            border-left: 4px solid #DC2626;
        }}

        .high-risk-row:hover {{
            background: #FEE2E2 !important;
        }}

        .high-risk-badge {{
            background: #DC2626;
            color: white;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.75rem;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 3rem;
            color: var(--text-secondary);
        }}
        
        /* 漏洞详情展开样式 */
        .vuln-row {{
            cursor: pointer;
            transition: background-color 0.2s;
        }}
        
        .vuln-row:hover {{
            background-color: #f3f4f6;
        }}
        
        .expand-icon {{
            display: inline-block;
            transition: transform 0.2s;
            font-size: 0.8rem;
            color: #6b7280;
        }}
        
        .expand-icon.expanded {{
            transform: rotate(180deg);
        }}
        
        .vuln-detail-row {{
            background-color: #f9fafb;
        }}
        
        .vuln-detail-content {{
            padding: 1rem;
        }}
        
        .http-section {{
            margin-bottom: 1rem;
            text-align: center;
        }}

        .http-section:last-child {{
            margin-bottom: 0;
        }}

        .http-title {{
            font-weight: 600;
            font-size: 0.85rem;
            color: #374151;
            margin-bottom: 0.5rem;
            padding: 0.25rem 0.5rem;
            background: #e5e7eb;
            border-radius: 4px;
            display: inline-block;
        }}
        
        .http-content {{
            background: #1f2937;
            color: #e5e7eb;
            padding: 1rem;
            border-radius: 6px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 0.8rem;
            line-height: 1.5;
            overflow-x: auto;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 400px;
            overflow-y: auto;
            text-align: left;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1><i class="bi bi-shield-check"></i> FLUX 安全扫描报告</h1>
            <p class="mb-0 mt-2" style="opacity: 0.8;">全面的Web安全漏洞扫描 · 敏感信息检测</p>
            <div class="target-url mt-3">{target_list}</div>
            <p class="mb-0 mt-2" style="opacity: 0.6;">扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
    
    <div class="container">
        <div class="row g-2 mb-3">
            <div class="col-6 col-md-3">
                <div class="stat-card critical" onclick="filterSeverityAndSwitch('Critical')" style="cursor:pointer">
                    <div class="stat-number">{severity_stats['critical']}</div>
                    <div class="stat-label">严重</div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stat-card high" onclick="filterSeverityAndSwitch('High')" style="cursor:pointer">
                    <div class="stat-number">{severity_stats['high']}</div>
                    <div class="stat-label">高危</div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stat-card medium" onclick="filterSeverityAndSwitch('Medium')" style="cursor:pointer">
                    <div class="stat-number">{severity_stats['medium']}</div>
                    <div class="stat-label">中危</div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stat-card low" onclick="filterSeverityAndSwitch('Low')" style="cursor:pointer">
                    <div class="stat-number">{severity_stats['low']}</div>
                    <div class="stat-label">低危</div>
                </div>
            </div>
        </div>

        <!-- API端点与请求方式 -->
        <div class="row g-2 mb-3 api-method-row">
            <div class="col-12 col-md-2">
                <div class="stat-card api-endpoint-card" onclick="switchTab('endpoints', event)" style="cursor:pointer">
                    <div class="stat-number" style="color: #818CF8">{len(endpoints)}</div>
                    <div class="stat-label">API端点</div>
                </div>
            </div>
            <div class="col-12 col-md-10">
                <div class="method-stats-container">
                    <div class="method-stat" onclick="filterEndpointsByMethod('GET')" style="cursor:pointer">
                        <span class="method-badge" style="background: #22C55E;">GET</span>
                        <span class="method-count">{len(endpoints_get)}</span>
                    </div>
                    <div class="method-stat" onclick="filterEndpointsByMethod('POST')" style="cursor:pointer">
                        <span class="method-badge" style="background: #3B82F6;">POST</span>
                        <span class="method-count">{len(endpoints_post)}</span>
                    </div>
                    <div class="method-stat" onclick="filterEndpointsByMethod('PUT')" style="cursor:pointer">
                        <span class="method-badge" style="background: #F59E0B;">PUT</span>
                        <span class="method-count">{len(endpoints_put)}</span>
                    </div>
                    <div class="method-stat" onclick="filterEndpointsByMethod('DELETE')" style="cursor:pointer">
                        <span class="method-badge" style="background: #EF4444;">DELETE</span>
                        <span class="method-count">{len(endpoints_delete)}</span>
                    </div>
                    <div class="method-stat" onclick="filterEndpointsByMethod('PATCH')" style="cursor:pointer">
                        <span class="method-badge" style="background: #8B5CF6;">PATCH</span>
                        <span class="method-count">{len(endpoints_patch)}</span>
                    </div>
                    <div class="method-stat" onclick="filterEndpointsByMethod('OPTIONS')" style="cursor:pointer">
                        <span class="method-badge" style="background: #EC4899;">OPTIONS</span>
                        <span class="method-count">{len(endpoints_options)}</span>
                    </div>
                    <div class="method-stat" onclick="filterEndpointsByMethod('HEAD')" style="cursor:pointer">
                        <span class="method-badge" style="background: #14B8A6;">HEAD</span>
                        <span class="method-count">{len(endpoints_head)}</span>
                    </div>
                    <div class="method-stat" onclick="filterEndpointsByMethod('WS')" style="cursor:pointer">
                        <span class="method-badge" style="background: #10B981;">WS</span>
                        <span class="method-count">{len(endpoints_ws)}</span>
                    </div>
                    <div class="method-stat" onclick="filterEndpointsByMethod('OTHER')" style="cursor:pointer">
                        <span class="method-badge" style="background: #6B7280;">其他</span>
                        <span class="method-count">{len(endpoints_other)}</span>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- 高危接口统计 -->
        <div class="row g-2 mb-3">
            <div class="col-6 col-md-3">
                <div class="stat-card high" onclick="filterEndpointsByRisk('High')" style="cursor:pointer; border: 2px solid #EF4444;">
                    <div class="stat-number" style="color: #EF4444;">{high_risk_count}</div>
                    <div class="stat-label" style="color: #EF4444; font-weight: bold; font-size: 0.65rem;">[高风险] 高危接口</div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stat-card" onclick="filterDeleteEndpoints()" style="cursor:pointer; border: 2px solid #DC2626;">
                    <div class="stat-number" style="color: #DC2626;">{delete_count}</div>
                    <div class="stat-label" style="color: #DC2626; font-weight: bold; font-size: 0.65rem;">[DELETE] 删除接口</div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stat-card" onclick="filterUploadEndpoints();" style="cursor:pointer; border: 2px solid #F59E0B;">
                    <div class="stat-number" style="color: #F59E0B;">{upload_count}</div>
                    <div class="stat-label" style="color: #F59E0B; font-weight: bold; font-size: 0.65rem;">[UPLOAD] 上传接口</div>
                </div>
            </div>
            <div class="col-6 col-md-3">
                <div class="stat-card" onclick="filterAdminEndpoints();" style="cursor:pointer; border: 2px solid #8B5CF6;">
                    <div class="stat-number" style="color: #8B5CF6;">{admin_count}</div>
                    <div class="stat-label" style="color: #8B5CF6; font-weight: bold; font-size: 0.65rem;">[ADMIN] 管理接口</div>
                </div>
            </div>
        </div>

        <div class="row g-2 mb-3">
            <div class="col-6 col-md-2">
                <div class="stat-card" onclick="switchTab('jsfiles')" style="cursor:pointer">
                    <div class="stat-number" style="color: #6366F1">{js_files_count}</div>
                    <div class="stat-label">JS文件</div>
                </div>
            </div>
            <div class="col-6 col-md-2">
                <div class="stat-card" onclick="switchTab('pages')" style="cursor:pointer">
                    <div class="stat-number" style="color: #8B5CF6">{pages_count}</div>
                    <div class="stat-label">页面</div>
                </div>
            </div>
            <div class="col-6 col-md-2">
                <div class="stat-card">
                    <div class="stat-number" style="color: #EC4899">{forms_count}</div>
                    <div class="stat-label">表单</div>
                </div>
            </div>
            <div class="col-6 col-md-2">
                <div class="stat-card" onclick="switchTab('findings'); document.getElementById('typeFilter').value='cloud_keys'; filterFindings();" style="cursor:pointer">
                    <div class="stat-number" style="color: #F59E0B">{cloud_keys_count}</div>
                    <div class="stat-label">云密钥</div>
                </div>
            </div>
            <div class="col-6 col-md-2">
                <div class="stat-card" onclick="switchTab('findings'); document.getElementById('typeFilter').value='auth_tokens'; filterFindings();" style="cursor:pointer">
                    <div class="stat-number" style="color: #10B981">{auth_tokens_count}</div>
                    <div class="stat-label">认证令牌</div>
                </div>
            </div>
            <div class="col-6 col-md-2">
                <div class="stat-card" onclick="switchTab('findings'); document.getElementById('typeFilter').value='hardcoded_creds'; filterFindings();" style="cursor:pointer">
                    <div class="stat-number" style="color: #F97316">{hardcoded_creds_count}</div>
                    <div class="stat-label">硬编码</div>
                </div>
            </div>
        </div>
        
        <div class="section-card">
            <div class="tabs">
                <button class="tab active" onclick="switchTab('findings')">敏感信息 ({len(results)})</button>
                <button class="tab" onclick="switchTab('jsfiles')">JS文件 ({js_files_count})</button>
                <button class="tab" onclick="switchTab('pages')">页面 ({pages_count})</button>
                <button class="tab" onclick="switchTab('endpoints')">API端点 ({len(endpoints)})</button>
                <button class="tab" onclick="switchTab('absoluteApis')">绝对路径 ({absolute_apis_count})</button>
                <button class="tab" onclick="switchTab('relativeApis')">相对路径 ({relative_apis_count})</button>
                <button class="tab" onclick="switchTab('modules')">模块路径 ({module_paths_count})</button>
                <button class="tab" onclick="switchTab('routes')">前端路由 ({frontend_routes_count})</button>
                <button class="tab" onclick="switchTab('vulns')">漏洞发现 ({len(vuln_findings) if vuln_findings else 0})</button>
                <button class="tab" onclick="switchTab('subdomains')">子域名 ({len(subdomains) if subdomains else 0})</button>
                <button class="tab" onclick="switchTab('fingerprints')">指纹识别 ({len(fingerprint_results) if fingerprint_results else 0})</button>
                <button class="tab" onclick="switchTab('apidocs')">API文档 ({len(api_docs) if api_docs else 0})</button>
            </div>
            
            <div id="findings" class="tab-content active">
                <div class="filter-bar">
                    <select id="severityFilter" onchange="filterFindings()">
                        <option value="all">全部严重等级</option>
                        <option value="Critical">严重</option>
                        <option value="High">高危</option>
                        <option value="Medium">中危</option>
                        <option value="Low">低危</option>
                    </select>
                    <select id="typeFilter" onchange="filterFindings()">
                        <option value="all">全部类型</option>
                        <option value="cloud_keys">云API密钥</option>
                        <option value="auth_tokens">认证令牌</option>
                        <option value="personal_info">个人信息</option>
                        <option value="hardcoded_creds">硬编码凭据</option>
                        <option value="backup_files">备份文件</option>
                        <option value="sensitive_path">敏感路径</option>
                        <option value="jsonp">JSONP接口</option>
                        <option value="cors">跨域配置</option>
                        <option value="ssrf">SSRF漏洞</option>
                    </select>
                    <span id="filterCount" style="color: var(--text-secondary)"></span>
                </div>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>严重等级<br><span style="font-size:0.7rem;color:#999">危险程度</span></th>
                                <th>类型<br><span style="font-size:0.7rem;color:#999">漏洞类型</span></th>
                                <th>发现内容<br><span style="font-size:0.7rem;color:#999">漏洞位置</span></th>
                                <th>详情<br><span style="font-size:0.7rem;color:#999">详细描述</span></th>
                                <th>来源<br><span style="font-size:0.7rem;color:#999">数据来源</span></th>
                            </tr>
                        </thead>
                        <tbody id="findingsTable">
                            {generate_findings_table(results)}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div id="jsfiles" class="tab-content">
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>JS文件URL</th>
                                <th>来源页面</th>
                            </tr>
                        </thead>
                        <tbody id="jsFilesTable">
                            {generate_js_files_table(js_files_list)}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div id="pages" class="tab-content">
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>页面URL</th>
                                <th>状态</th>
                            </tr>
                        </thead>
                        <tbody id="pagesTable">
                            {generate_pages_table(pages_list)}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div id="endpoints" class="tab-content">
                <div class="filter-bar">
                    <select id="methodFilter" onchange="filterEndpoints()">
                        <option value="all">全部方法</option>
                        <option value="GET">GET</option>
                        <option value="POST">POST</option>
                        <option value="PUT">PUT</option>
                        <option value="DELETE">DELETE</option>
                        <option value="PATCH">PATCH</option>
                        <option value="WS">WebSocket</option>
                        <option value="OTHER">其他</option>
                    </select>
                    <select id="riskFilter" onchange="filterEndpoints()">
                        <option value="all">全部风险</option>
                        <option value="High">高风险</option>
                        <option value="Medium">中风险</option>
                        <option value="Low">低风险</option>
                    </select>
                    <span id="endpointFilterCount" style="color: var(--text-secondary)"></span>
                </div>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>方法<br><span style="font-size:0.7rem;color:#999">请求方法</span></th>
                                <th>URL</th>
                                <th>接口类型<br><span style="font-size:0.7rem;color:#999">接口分类</span></th>
                                <th>风险等级<br><span style="font-size:0.7rem;color:#999">危险级别</span></th>
                                <th>风险类型<br><span style="font-size:0.7rem;color:#999">风险标识</span></th>
                            </tr>
                        </thead>
                        <tbody id="endpointsTable">
                            {generate_endpoints_table(endpoints)}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div id="absoluteApis" class="tab-content">
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>URL</th>
                                <th>来源</th>
                            </tr>
                        </thead>
                        <tbody>
                            {generate_absolute_apis_table(endpoints)}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div id="relativeApis" class="tab-content">
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>URL</th>
                                <th>接口类型</th>
                                <th>来源</th>
                            </tr>
                        </thead>
                        <tbody>
                            {generate_relative_apis_table(endpoints)}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div id="modules" class="tab-content">
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>模块路径</th>
                                <th>来源</th>
                            </tr>
                        </thead>
                        <tbody>
                            {generate_modules_table(endpoints)}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div id="routes" class="tab-content">
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>路由路径</th>
                                <th>接口类型</th>
                                <th>来源</th>
                            </tr>
                        </thead>
                        <tbody>
                            {generate_routes_table(endpoints)}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div id="vulns" class="tab-content">
                <div class="table-wrapper">
                    <table class="vuln-table">
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>严重等级</th>
                                <th>漏洞类型</th>
                                <th>URL</th>
                                <th>参数</th>
                                <th>Payload</th>
                                <th>详情</th>
                                <th>证据</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            {generate_vulns_table(vuln_findings) if vuln_findings else '<tr><td colspan="9" class="empty-state">未进行漏洞测试或未发现漏洞</td></tr>'}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div id="subdomains" class="tab-content">
                {generate_subdomains_section(subdomains) if subdomains else '<div class="empty-state">未发现子域名</div>'}
            </div>
            
            <div id="fingerprints" class="tab-content">
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>组件名称</th>
                                <th>类别</th>
                                <th>置信度</th>
                                <th>证据</th>
                            </tr>
                        </thead>
                        <tbody>
                            {generate_fingerprint_table(fingerprint_results)}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <div id="apidocs" class="tab-content">
                <h3>API文档列表</h3>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>文档标题</th>
                                <th>类型</th>
                                <th>版本</th>
                                <th>端点数量</th>
                            </tr>
                        </thead>
                        <tbody>
                            {generate_api_docs_table(api_docs)}
                        </tbody>
                    </table>
                </div>
                <h3 style="margin-top: 20px;">API端点详情</h3>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>#</th>
                                <th>方法</th>
                                <th>路径</th>
                                <th>描述</th>
                                <th>参数数</th>
                                <th>认证</th>
                            </tr>
                        </thead>
                        <tbody>
                            {generate_api_doc_endpoints_table(api_docs)}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <div class="toast" id="toast">已复制到剪贴板</div>
    
    <script>
        function filterSeverityAndSwitch(severity) {{
            document.getElementById('severityFilter').value = severity;
            switchTab('findings');
            filterFindings();
        }}
        
        function switchTab(tabId, event) {{
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            if (event) {{
                event.target.classList.add('active');
            }} else {{
                document.querySelector('.tab[onclick*="' + tabId + '"]').classList.add('active');
            }}
            document.getElementById(tabId).classList.add('active');
        }}
        
        function filterEndpointsByMethod(method) {{
            switchTab('endpoints');
            setTimeout(() => {{
                document.getElementById('methodFilter').value = method;
                document.getElementById('riskFilter').value = 'all';
                filterEndpoints();
            }}, 100);
        }}

        function filterEndpointsByRisk(risk) {{
            switchTab('endpoints');
            setTimeout(() => {{
                document.getElementById('riskFilter').value = risk;
                document.getElementById('methodFilter').value = 'all';
                filterEndpoints();
            }}, 100);
        }}

        function filterDeleteEndpoints() {{
            // 筛选DELETE方法 或 URL包含delete的接口
            switchTab('endpoints');
            setTimeout(() => {{
                document.getElementById('riskFilter').value = 'all';
                document.getElementById('methodFilter').value = 'all';
                const rows = document.querySelectorAll('#endpointsTable tr');
                let visible = 0;

                rows.forEach(row => {{
                    const method = row.getAttribute('data-method');
                    const urlCell = row.querySelector('td:nth-child(3)');  // URL在第3列（有序号列）
                    const url = urlCell ? urlCell.textContent.toLowerCase() : '';

                    // 匹配DELETE方法 或 URL包含delete/remove
                    if (method === 'DELETE' || url.includes('delete') || url.includes('remove')) {{
                        row.style.display = '';
                        visible++;
                        // 重新编号序号
                        const indexCell = row.querySelector('td:nth-child(1)');
                        if (indexCell) indexCell.textContent = visible;
                    }} else {{
                        row.style.display = 'none';
                    }}
                }});

                document.getElementById('endpointFilterCount').textContent = visible > 0 ? `显示 ${{visible}} 条` : '';
            }}, 100);
        }}

        function filterUploadEndpoints() {{
            // 筛选URL包含upload的接口
            switchTab('endpoints');
            setTimeout(() => {{
                document.getElementById('riskFilter').value = 'all';
                document.getElementById('methodFilter').value = 'all';
                const rows = document.querySelectorAll('#endpointsTable tr');
                let visible = 0;

                rows.forEach(row => {{
                    const urlCell = row.querySelector('td:nth-child(3)');  // URL在第3列（有序号列）
                    const url = urlCell ? urlCell.textContent.toLowerCase() : '';

                    if (url.includes('upload')) {{
                        row.style.display = '';
                        visible++;
                        // 重新编号序号
                        const indexCell = row.querySelector('td:nth-child(1)');
                        if (indexCell) indexCell.textContent = visible;
                    }} else {{
                        row.style.display = 'none';
                    }}
                }});

                document.getElementById('endpointFilterCount').textContent = visible > 0 ? `显示 ${{visible}} 条` : '';
            }}, 100);
        }}

        function filterAdminEndpoints() {{
            // 筛选URL包含admin或manage的接口
            switchTab('endpoints');
            setTimeout(() => {{
                document.getElementById('riskFilter').value = 'all';
                document.getElementById('methodFilter').value = 'all';
                const rows = document.querySelectorAll('#endpointsTable tr');
                let visible = 0;

                rows.forEach(row => {{
                    const urlCell = row.querySelector('td:nth-child(3)');  // URL在第3列（有序号列）
                    const url = urlCell ? urlCell.textContent.toLowerCase() : '';

                    if (url.includes('admin') || url.includes('manage')) {{
                        row.style.display = '';
                        visible++;
                        // 重新编号序号
                        const indexCell = row.querySelector('td:nth-child(1)');
                        if (indexCell) indexCell.textContent = visible;
                    }} else {{
                        row.style.display = 'none';
                    }}
                }});

                document.getElementById('endpointFilterCount').textContent = visible > 0 ? `显示 ${{visible}} 条` : '';
            }}, 100);
        }}

        function filterEndpointsByKeyword(keyword) {{
            document.getElementById('riskFilter').value = 'all';
            document.getElementById('methodFilter').value = 'all';
            const rows = document.querySelectorAll('#endpointsTable tr');
            let visible = 0;

            rows.forEach(row => {{
                const urlCell = row.querySelector('td:nth-child(3)');  // URL在第3列（有序号列）
                if (urlCell) {{
                    const url = urlCell.textContent.toLowerCase();
                    if (url.includes(keyword.toLowerCase())) {{
                        row.style.display = '';
                        visible++;
                        // 重新编号序号
                        const indexCell = row.querySelector('td:nth-child(1)');
                        if (indexCell) indexCell.textContent = visible;
                    }} else {{
                        row.style.display = 'none';
                    }}
                }}
            }});

            document.getElementById('endpointFilterCount').textContent = visible > 0 ? `显示 ${{visible}} 条` : '';
        }}

        function filterFindings() {{
            const severity = document.getElementById('severityFilter').value;
            const type = document.getElementById('typeFilter').value;
            const rows = document.querySelectorAll('#findingsTable tr');
            let visible = 0;
            
            rows.forEach(row => {{
                const rowSeverity = row.getAttribute('data-severity');
                const rowType = row.getAttribute('data-type');
                
                const severityMatch = severity === 'all' || rowSeverity === severity;
                const typeMatch = type === 'all' || rowType === type;
                
                if (severityMatch && typeMatch) {{
                    row.style.display = '';
                    visible++;
                    // 重新编号序号
                    const indexCell = row.querySelector('td:nth-child(1)');
                    if (indexCell) indexCell.textContent = visible;
                }} else {{
                    row.style.display = 'none';
                }}
            }});
            
            document.getElementById('filterCount').textContent = visible > 0 ? `显示 ${{visible}} 条` : '';
        }}
        
        function filterEndpoints() {{
            const method = document.getElementById('methodFilter').value;
            const risk = document.getElementById('riskFilter').value;
            const rows = document.querySelectorAll('#endpointsTable tr');
            let visible = 0;
            
            rows.forEach(row => {{
                const rowMethod = row.getAttribute('data-method');
                const rowRisk = row.getAttribute('data-risk');

                let methodMatch = false;
                if (method === 'all') {{
                    methodMatch = true;
                }} else if (method === 'OTHER') {{
                    methodMatch = rowMethod && !['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'WS', 'WEBSOCKET'].includes(rowMethod);
                }} else {{
                    methodMatch = rowMethod === method;
                }}
                
                const riskMatch = risk === 'all' || rowRisk === risk;
                
                if (methodMatch && riskMatch) {{
                    row.style.display = '';
                    visible++;
                    // 重新编号序号
                    const indexCell = row.querySelector('td:nth-child(1)');
                    if (indexCell) indexCell.textContent = visible;
                }} else {{
                    row.style.display = 'none';
                }}
            }});
            
            document.getElementById('endpointCount').textContent = visible > 0 ? `显示 ${{visible}} 条` : '';
        }}
        
        document.querySelectorAll('.copyable').forEach(cell => {{
            cell.addEventListener('click', function() {{
                const text = this.getAttribute('title') || this.textContent;
                navigator.clipboard.writeText(text).then(() => {{
                    showToast();
                }});
            }});
        }});
        
        function showToast() {{
            const toast = document.getElementById('toast');
            toast.classList.add('show');
            setTimeout(() => toast.classList.remove('show'), 2000);
        }}
        
        // 切换漏洞详情展开/折叠
        function toggleVulnDetail(vulnId) {{
            const detailRow = document.getElementById(vulnId);
            const icon = document.getElementById('icon_' + vulnId);
            
            if (detailRow.style.display === 'none') {{
                detailRow.style.display = 'table-row';
                icon.classList.add('expanded');
            }} else {{
                detailRow.style.display = 'none';
                icon.classList.remove('expanded');
            }}
        }}
        
        filterFindings();
        filterEndpoints();
    </script>
</body>
</html>'''


def generate_findings_table(results: List[Any]) -> str:
    if not results:
        return '<tr><td colspan="6" class="empty-state">未发现敏感信息</td></tr>'
    
    rows = []
    for i, r in enumerate(results, 1):
        type_name = TYPE_NAME_MAP.get(r.type, r.type)
        severity_class = r.severity.lower()
        
        finding_text = html.escape(r.finding) if r.finding else '-'
        detail_text = html.escape(r.detail) if r.detail else '-'
        source_text = html.escape(r.source) if r.source else '-'
        
        rows.append(f'''<tr data-severity="{r.severity}" data-type="{r.type}">
            <td>{i}</td>
            <td><span class="severity {severity_class}">{r.severity}</span></td>
            <td><span class="type-badge">{type_name}</span></td>
            <td><div class="copyable" title="{finding_text}">{finding_text}</div></td>
            <td><div class="copyable" title="{detail_text}">{detail_text}</div></td>
            <td><div class="copyable" title="{source_text}">{source_text}</div></td>
        </tr>''')
    
    return ''.join(rows)


def generate_endpoints_table(endpoints: List[Any]) -> str:
    if not endpoints:
        return '<tr><td colspan="6" class="empty-state">未发现API端点</td></tr>'

    rows = []
    for i, e in enumerate(endpoints, 1):
        method_class = e.method.lower()
        risk_class = e.risk_level.lower()

        api_type = get_api_type(e.url)

        # 判断是否为高风险或DELETE接口
        is_high_risk = e.risk_level == "High"
        is_delete = getattr(e, 'is_delete', False) or e.method.upper() == "DELETE"

        # 构建警告标签
        warnings = []
        if is_delete:
            warnings.append('<span class="delete-warning">[DELETE] 删除接口</span>')
        if is_high_risk:
            warnings.append('<span class="high-risk-badge">[HIGH] 高风险</span>')

        warning_html = '<br>'.join(warnings) if warnings else ''

        # 行样式：高风险或DELETE接口使用特殊样式
        row_class = 'high-risk-row' if (is_high_risk or is_delete) else ''

        url_text = html.escape(e.url) if e.url else "-"
        risks_text = ', '.join([html.escape(r) for r in e.risks]) if e.risks else "-"

        rows.append(f'''<tr class="{row_class}" data-method="{e.method}" data-risk="{e.risk_level}">
            <td>{i}</td>
            <td><span class="method {method_class}">{e.method}</span></td>
            <td><div class="copyable" title="{url_text}">{url_text}</div></td>
            <td><span class="type-badge">{html.escape(api_type)}</span></td>
            <td><span class="severity {risk_class}">{e.risk_level}</span>{'<br>' + warning_html if warning_html else ''}</td>
            <td><div class="copyable" title="{risks_text}">{risks_text}</div></td>
        </tr>''')
    
    return ''.join(rows)


def generate_vulns_table(vuln_findings: List[Any]) -> str:
    if not vuln_findings:
        return '<tr><td colspan="9" class="empty-state">未发现漏洞</td></tr>'
    
    rows = []
    for i, v in enumerate(vuln_findings, 1):
        severity_class = v.severity.lower()
        vuln_type = VULN_TYPE_MAP.get(v.vuln_type, v.vuln_type)
        
        evidence = html.escape(v.evidence) if hasattr(v, 'evidence') and v.evidence else "-"
        detail = html.escape(v.detail) if v.detail else "-"
        url_text = html.escape(v.url) if v.url else "-"
        param_text = html.escape(v.param) if v.param else "-"
        payload_text = html.escape(v.payload) if v.payload else "-"
        
        # 获取请求和响应包
        request_str = html.escape(getattr(v, 'request', '')) if hasattr(v, 'request') and v.request else "-"
        response_str = html.escape(getattr(v, 'response', '')) if hasattr(v, 'response') and v.response else "-"
        
        # 生成唯一的ID用于展开/折叠
        vuln_id = f"vuln_{i}"
        
        rows.append(f'''<tr class="vuln-row" onclick="toggleVulnDetail('{vuln_id}')">
            <td>{i}</td>
            <td><span class="severity {severity_class}">{v.severity}</span></td>
            <td>{html.escape(vuln_type)}</td>
            <td><div class="copyable" title="{url_text}">{url_text}</div></td>
            <td><div class="copyable" title="{param_text}">{param_text}</div></td>
            <td><div class="copyable" title="{payload_text}">{payload_text}</div></td>
            <td><div class="copyable" title="{detail}">{detail}</div></td>
            <td><div class="copyable" title="{evidence}">{evidence}</div></td>
            <td><span class="expand-icon" id="icon_{vuln_id}">▼</span></td>
        </tr>
        <tr id="{vuln_id}" class="vuln-detail-row" style="display:none;">
            <td colspan="9">
                <div class="vuln-detail-content">
                    <div class="http-section">
                        <div class="http-title">请求包 (HTTP Request):</div>
                        <pre class="http-content">{request_str}</pre>
                    </div>
                    <div class="http-section">
                        <div class="http-title">响应包 (HTTP Response):</div>
                        <pre class="http-content">{response_str}</pre>
                    </div>
                </div>
            </td>
        </tr>''')
    
    return ''.join(rows)


def generate_subdomains_section(subdomains: List[str]) -> str:
    if not subdomains:
        return '<div class="empty-state">未发现子域名</div>'
    
    tags = [f'<span class="subdomain-tag">{html.escape(s)}</span>' for s in sorted(subdomains)]
    return '<div class="p-3">' + ''.join(tags) + '</div>'


def generate_js_files_table(js_files_list: List[Any]) -> str:
    if not js_files_list:
        return '<tr><td colspan="3" class="empty-state">未发现JS文件</td></tr>'
    
    rows = []
    for i, js in enumerate(js_files_list, 1):
        js_url = js.get('url', '')
        source = html.escape(js.get('source', ''))
        
        # 处理内联脚本
        if js_url.startswith('inline:'):
            parts = js_url.split(':', 3)
            if len(parts) >= 4:
                # 显示为"内联脚本 #index"，并截断内容预览
                content_preview = parts[3][:80] if len(parts) > 3 else ''
                # 清理预览内容
                content_preview = re.sub(r'\s+', ' ', content_preview).strip()
                if len(content_preview) > 80:
                    content_preview = content_preview[:80] + '...'
                js_url_display = f"[内联脚本 #{parts[1]}] {html.escape(content_preview)}"
            else:
                js_url_display = f"[内联脚本 #{parts[1] if len(parts) > 1 else 'N/A'}]"
        else:
            js_url_display = html.escape(js_url)
        
        rows.append(f'''<tr>
            <td>{i}</td>
            <td><div class="copyable" title="{js_url_display}">{js_url_display}</div></td>
            <td><div class="copyable" title="{source}">{source}</div></td>
        </tr>''')
    return ''.join(rows)


def generate_pages_table(pages_list: List[Any]) -> str:
    if not pages_list:
        return '<tr><td colspan="3" class="empty-state">未发现页面</td></tr>'
    
    rows = []
    for i, page in enumerate(pages_list, 1):
        page_url = html.escape(page.get('url', ''))
        status = page.get('status', 'unknown')
        status_display = f'<span class="severity low">200</span>' if status == 200 else f'<span class="severity medium">{status}</span>'
        rows.append(f'''<tr>
            <td>{i}</td>
            <td><div class="copyable" title="{page_url}">{page_url}</div></td>
            <td>{status_display}</td>
        </tr>''')
    return ''.join(rows)


def generate_absolute_apis_table(endpoints: List[Any]) -> str:
    absolute_endpoints = [e for e in endpoints if getattr(e, 'is_absolute', False)]
    if not absolute_endpoints:
        return '<tr><td colspan="3" class="empty-state">未发现绝对路径API</td></tr>'
    
    rows = []
    for i, e in enumerate(absolute_endpoints, 1):
        url_text = html.escape(e.url) if e.url else "-"
        source = html.escape(e.source_js) if e.source_js else "-"
        rows.append(f'''<tr>
            <td>{i}</td>
            <td><div class="copyable" title="{url_text}">{url_text}</div></td>
            <td><div class="copyable" title="{source}">{source}</div></td>
        </tr>''')
    return ''.join(rows)


def generate_relative_apis_table(endpoints: List[Any]) -> str:
    relative_endpoints = [e for e in endpoints if not getattr(e, 'is_absolute', True) and not getattr(e, 'is_module', False)]
    if not relative_endpoints:
        return '<tr><td colspan="4" class="empty-state">未发现相对路径API</td></tr>'
    
    rows = []
    for i, e in enumerate(relative_endpoints, 1):
        url_text = html.escape(e.url) if e.url else "-"
        api_type = html.escape(getattr(e, 'api_type', '通用接口'))
        source = html.escape(e.source_js) if e.source_js else "-"
        rows.append(f'''<tr>
            <td>{i}</td>
            <td><div class="copyable" title="{url_text}">{url_text}</div></td>
            <td><span class="type-badge">{api_type}</span></td>
            <td><div class="copyable" title="{source}">{source}</div></td>
        </tr>''')
    return ''.join(rows)


def generate_fingerprint_table(fingerprint_results: List[Any]) -> str:
    """生成指纹识别结果表格"""
    if not fingerprint_results:
        return '<tr><td colspan="5" class="empty-state">未识别到指纹</td></tr>'
    
    category_names = {
        'frameworks': 'Web框架',
        'cms': 'CMS系统',
        'servers': '服务器软件',
        'languages': '编程语言',
        'waf_cdn': 'WAF/CDN',
        'databases': '数据库',
        'frontend': '前端框架',
        'path': '路径特征'
    }
    
    rows = []
    for i, fp in enumerate(fingerprint_results, 1):
        category_name = category_names.get(fp.category, fp.category)
        confidence_color = 'green' if fp.confidence >= 80 else 'orange' if fp.confidence >= 50 else 'red'
        
        rows.append(f'''<tr>
            <td>{i}</td>
            <td>{fp.icon} {html.escape(fp.name)}</td>
            <td>{category_name}</td>
            <td><span style="color: {confidence_color}">{fp.confidence}%</span></td>
            <td><div class="copyable" title="{html.escape(fp.evidence)}">{html.escape(fp.evidence[:100])}</div></td>
        </tr>''')
    
    return ''.join(rows)


def generate_api_docs_table(api_docs: List[Any]) -> str:
    """生成API文档信息表格"""
    if not api_docs:
        return '<tr><td colspan="5" class="empty-state">未发现API文档</td></tr>'
    
    rows = []
    for i, doc in enumerate(api_docs, 1):
        doc_type_names = {
            'swagger-v2': 'Swagger 2.0',
            'openapi-v3': 'OpenAPI 3.0',
            'postman': 'Postman Collection',
            'wadl': 'WADL'
        }
        doc_type = doc_type_names.get(doc.doc_type, doc.doc_type)
        
        rows.append(f'''<tr>
            <td>{i}</td>
            <td>{html.escape(doc.title)}</td>
            <td>{doc_type}</td>
            <td>{doc.version}</td>
            <td>{len(doc.endpoints)}</td>
        </tr>''')
    
    return ''.join(rows)


def generate_api_doc_endpoints_table(api_docs: List[Any]) -> str:
    """生成API文档中的端点表格"""
    if not api_docs:
        return '<tr><td colspan="6" class="empty-state">无API文档端点</td></tr>'
    
    rows = []
    count = 0
    for doc in api_docs:
        for ep in doc.endpoints:
            count += 1
            method_class = ep.method.lower() if ep.method else 'get'
            auth_badge = '<span class="badge-auth">需要认证</span>' if ep.auth_required else ''
            
            rows.append(f'''<tr>
                <td>{count}</td>
                <td><span class="method {method_class}">{ep.method}</span></td>
                <td><div class="copyable" title="{html.escape(ep.path)}">{html.escape(ep.path)}</div></td>
                <td>{html.escape(ep.summary or '-')}</td>
                <td>{len(ep.parameters)}</td>
                <td>{auth_badge}</td>
            </tr>''')
    
    return ''.join(rows)


def generate_modules_table(endpoints: List[Any]) -> str:
    module_endpoints = [e for e in endpoints if getattr(e, 'is_module', False)]
    if not module_endpoints:
        return '<tr><td colspan="3" class="empty-state">未发现模块路径</td></tr>'
    
    rows = []
    for i, e in enumerate(module_endpoints, 1):
        url_text = html.escape(e.url) if e.url else "-"
        source = html.escape(e.source_js) if e.source_js else "-"
        rows.append(f'''<tr>
            <td>{i}</td>
            <td><div class="copyable" title="{url_text}">{url_text}</div></td>
            <td><div class="copyable" title="{source}">{source}</div></td>
        </tr>''')
    return ''.join(rows)


def generate_routes_table(endpoints: List[Any]) -> str:
    route_endpoints = [e for e in endpoints if getattr(e, 'is_route', False)]
    if not route_endpoints:
        return '<tr><td colspan="4" class="empty-state">未发现前端路由</td></tr>'
    
    rows = []
    for i, e in enumerate(route_endpoints, 1):
        url_text = html.escape(e.url) if e.url else "-"
        api_type = html.escape(getattr(e, 'api_type', '通用接口'))
        source = html.escape(e.source_js) if e.source_js else "-"
        rows.append(f'''<tr>
            <td>{i}</td>
            <td><div class="copyable" title="{url_text}">{url_text}</div></td>
            <td><span class="type-badge">{api_type}</span></td>
            <td><div class="copyable" title="{source}">{source}</div></td>
        </tr>''')
    return ''.join(rows)
