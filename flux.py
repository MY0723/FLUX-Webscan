#!/usr/bin/env python3
"""
=============================================================================
   FLUX v3.1.0: 专业的Web安全扫描工具
=============================================================================
    核心特性:
    - 25,000+ 指纹库
    - 40+种WAF检测与绕过 (含国产厂商)
    - 差分测试机制 (误报率降低80%+)
    - DOM型XSS检测 (静态污点分析)
    - CSRF Token自动提取 / Cookie持久化
    - 智能速率限制 / 流量指纹伪装
    - API参数提取与Fuzzing
    - JS代码混淆还原
    - SwaggerHound API自动测试
    - SQL注入/XSS误报过滤

    作者: ROOT4044
    版本: 3.1.0
    日期: 2026-03-13
    许可证: MIT License
=============================================================================
"""

import re
import requests
import argparse
import json
import sys
import hashlib
import time
import warnings
from urllib.parse import urlparse, urljoin, urlunparse, quote, unquote, parse_qs
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import random
import os
import html
import threading
import math
import base64

warnings.filterwarnings('ignore')

from report_generator import generate_html_report_v3 as generate_html_report
from vuln_test import EnhancedVulnTester, detect_webpack, get_api_type, get_risk_description
from fingerprint_engine import FingerprintEngine, FingerprintResult
from api_parser import APIDocParser, APIEndpoint, ParsedAPIDoc, parse_api_docs
from swagger_hound import SwaggerHound


logging.basicConfig(
    level=logging.INFO,
    format='\033[92m[%(asctime)s]\033[0m [\033[93m%(levelname)s\033[0m] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    url: str
    type: str
    severity: str
    finding: str
    detail: str = ""
    source: str = ""
    verified: bool = False
    
    def __hash__(self):
        return hash((self.url, self.type, self.finding))
    
    def __eq__(self, other):
        if not isinstance(other, ScanResult):
            return False
        return (self.url == other.url and 
                self.type == other.type and 
                self.finding == other.finding)

@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    source_js: str = ""
    risk_level: str = "Low"
    risks: List[str] = field(default_factory=list)
    is_delete: bool = False
    api_type: str = "通用接口"
    is_absolute: bool = False
    is_module: bool = False
    is_route: bool = False

@dataclass
class VulnFinding:
    url: str
    vuln_type: str
    severity: str
    param: str = ""
    payload: str = ""
    detail: str = ""
    evidence: str = ""
    request: str = ""  # HTTP请求包
    response: str = ""  # HTTP响应包

@dataclass
class FormInput:
    url: str
    method: str = "POST"
    action: str = ""
    inputs: List[Dict[str, str]] = field(default_factory=list)
    form_type: str = "form"

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    ORANGE = '\033[38;5;208m'
    WHITE = '\033[97m'
    END = '\033[0m'

class FLUX:
    def __init__(self, target: str, depth: int = 3, 
                 timeout: int = 15, proxy: str = None,
                 threads: int = 20, verify_keys: bool = False,
                 fuzz_params: bool = False, vuln_test: bool = False,
                 fuzz_paths: bool = False, test_delete: bool = False,
                 api_parse: bool = False, verify_endpoints: bool = False,
                 save_interval: int = 30):
        
        if os.path.isfile(target):
            with open(target, 'r') as f:
                self.targets = [line.strip() for line in f if line.strip()]
        else:
            self.targets = [t.strip() for t in target.split(',')]
        
        self.depth = depth
        self.timeout = timeout
        self.proxy = proxy
        self.threads = threads
        self.verify_keys = verify_keys
        self.fuzz_params = fuzz_params
        self.vuln_test = vuln_test
        self.fuzz_paths = fuzz_paths
        self.test_delete = test_delete
        self.api_parse = api_parse
        self.verify_endpoints = verify_endpoints
        self.save_interval = save_interval
        
        self.last_save_time = time.time()
        self.scan_start_time = time.time()
        
        self.total_targets = len(self.targets)
        self.current_target_index = 0
        
        self.progress_stats = {
            'pages_scanned': 0,
            'js_analyzed': 0,
            'total_pages_estimate': 0,
            'total_js_estimate': 0,
        }
        
        # 线程锁保护共享资源
        self._lock = threading.Lock()
        
        self.visited_urls: Set[str] = set()
        self.visited_js: Set[str] = set()
        self.js_files: Set[str] = set()
        self.js_files_detail: List[Dict] = []
        self.crawled_pages: Set[str] = set()
        self.pages_detail: List[Dict] = []
        self.endpoints: List[Endpoint] = []
        self.endpoint_urls: Set[Tuple[str, str]] = set()
        self.subdomains: Set[str] = set()
        self.results: List[ScanResult] = []
        self.result_keys: Set[Tuple[str, str, str]] = set()
        self.vuln_findings: List[VulnFinding] = []
        self.vuln_keys: Set[Tuple[str, str, str]] = set()
        self.forms: List[FormInput] = []
        
        # 基准线缓存：存储正常请求的响应特征
        self.baseline_cache: Dict[str, Dict] = {}
        
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = timeout
        
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        
        self.target_url = self.targets[0] if self.targets else ""
        self.base_domain = urlparse(self.target_url).netloc if self.target_url else ""
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
            'Referer': self.target_url,
        }
        
        self.endpoint_patterns = self._init_endpoint_patterns()
        self.sensitive_patterns = self._init_all_rules()
        self.vuln_libs = self._init_vulnerable_libs()
        self.dangerous_funcs = self._init_dangerous_functions()
        
        self._init_vuln_tester()
        self._init_waf_modules()
        self._init_fingerprint_modules()
        
        # Web架构信息
        self.web_architecture: Dict = {}
        
        # CSRF Token管理
        self.csrf_tokens: Dict[str, str] = {}  # URL -> CSRF Token
        self.csrf_token_patterns = [
            r'<input[^>]*name=["\'](csrf_token|csrfmiddlewaretoken|_token|__RequestVerificationToken|authenticity_token)["\'][^>]*value=["\']([^"\']+)["\']',
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
            r'["\'](csrf_token|csrfToken|X-CSRF-Token)["\']\s*[:=]\s*["\']([^"\']+)["\']',
            r'window\._csrf\s*=\s*["\']([^"\']+)["\']',
            r'csrf\s*[:=]\s*["\']([a-zA-Z0-9]{32,})["\']',
        ]
        
        # Cookie持久化
        self.cookie_jar_file: Optional[str] = None
        self.session_cookies: Dict[str, Dict] = {}
        
        # 智能速率限制
        self.adaptive_rate_limit = True
        self.request_times: List[float] = []  # 记录最近请求时间
        self.rate_limit_stats = {
            'avg_response_time': 0.0,
            'error_count': 0,
            'success_count': 0,
            'current_delay': 0.0,
        }
        
        # 流量指纹伪装
        self.header_rotation_pool = self._init_header_pool()
        self.current_headers = self.headers.copy()
        
        # 盲注时间统计优化
        self.time_based_stats = {
            'baseline_times': [],  # 正常请求响应时间
            'payload_times': {},   # payload响应时间
        }

    def _init_all_rules(self) -> Dict[str, List[Dict]]:
        return {
            # ========== 云服务API密钥 ==========
            "cloud_keys": [
                {"name": "阿里云AccessKey", "pattern": r'\bLTAI[a-zA-Z0-9]{20,32}\b', "severity": "Critical"},
                {"name": "阿里云SecretKey", "pattern": r'\b[a-zA-Z0-9]{30}\b', "severity": "Critical", "context": r'(aliyun\.com|aliyuncs\.com|LTAI)', "min_len": 30},
                {"name": "腾讯云SecretId", "pattern": r'\bAKID[a-zA-Z0-9]{32}\b', "severity": "Critical", "context": r'(qcloud|tencentcloud)', "min_len": 32},
                {"name": "腾讯云SecretKey", "pattern": r'\b[a-zA-Z0-9]{32}\b', "severity": "Critical", "context": r'(qcloud\.com|tencentcloud\.com|secretKey)', "min_len": 32},
                {"name": "腾讯云TKE密钥", "pattern": r'\bTKE_[a-zA-Z0-9]{32}\b', "severity": "Critical"},
                {"name": "华为云AK", "pattern": r'\bAK[a-zA-Z0-9]{20,32}\b', "severity": "Critical", "context": r'(huaweicloud\.com|myhuaweicloud\.com|credential)', "min_len": 24},
                {"name": "华为云SK", "pattern": r'\bSK[a-zA-Z0-9]{32}\b', "severity": "Critical", "context": r'(huaweicloud\.com|myhuaweicloud\.com|credential)', "min_len": 32},
                {"name": "七牛云AccessKey", "pattern": r'\bQINIU[a-zA-Z0-9]{14}\b', "severity": "High"},
                {"name": "京东云AccessKey", "pattern": r'\b(?:JD|AK)[a-zA-Z0-9]{20,32}\b', "severity": "High", "context": r'(jdcloud\.com|ak)', "min_len": 24},
                {"name": "网易云API Key", "pattern": r'\bNtCloud-[a-zA-Z0-9]{32}\b', "severity": "High"},
                {"name": "金山云API Key", "pattern": r'\bKSY-(?:AK|SK)-[a-zA-Z0-9]{32}\b', "severity": "High"},
                {"name": "百度云AK", "pattern": r'\b[a-zA-Z0-9]{32}\b', "severity": "Medium", "context": r'(bce\.baidu\.com|ak\s*=|baiducloud)', "min_len": 32},
                {"name": "字节跳动API Key", "pattern": r'\b[a-zA-Z0-9]{20,32}\b', "severity": "High", "context": r'(bytedance|byte\.cn|今日头条)', "min_len": 24},
                {"name": "AWS Access Key", "pattern": r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b', "severity": "Critical"},
                {"name": "AWS Secret Key", "pattern": r'\b[A-Za-z0-9/+=]{40}\b', "severity": "Critical", "context": r'(aws\.amazon|secretKey|secret)', "min_len": 40},
                {"name": "Google API Key", "pattern": r'\bAIza[0-9A-Za-z_-]{35}\b', "severity": "Critical"},
                {"name": "Google Cloud Service Account", "pattern": r'-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----', "severity": "Critical"},
                {"name": "Azure Storage Key", "pattern": r'(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{44}', "severity": "Critical"},
                {"name": "Azure Client Secret", "pattern": r'(?i)(client[_-]?secret|app[_-]?secret)[^\s]{0,50}["\']?([a-zA-Z0-9~._-]{40,})', "severity": "Critical"},
                {"name": "Firebase API Key", "pattern": r'\bAIza[0-9A-Za-z_-]{35}\b', "severity": "High", "context": r'(firebase|firebaseremote)'},
                {"name": "Stripe API Key", "pattern": r'\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b', "severity": "Critical"},
                {"name": "GitHub Token", "pattern": r'\bghp_[a-zA-Z0-9]{36}\b', "severity": "Critical"},
                {"name": "GitHub OAuth", "pattern": r'\bgho_[a-zA-Z0-9]{36}\b', "severity": "Critical"},
                {"name": "GitHub App Token", "pattern": r'\b(?:ghu|ghs)_[a-zA-Z0-9]{36}\b', "severity": "Critical"},
                {"name": "Slack Token", "pattern": r'xox[baprs]-[0-9a-zA-Z]{10,48}', "severity": "High"},
                {"name": "Slack Webhook", "pattern": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+', "severity": "High"},
                {"name": "Telegram Bot Token", "pattern": r'\d{8,10}:[a-zA-Z0-9_-]{35}', "severity": "High"},
                {"name": "Discord Token", "pattern": r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}', "severity": "High"},
                {"name": "SendGrid API Key", "pattern": r'\bSG\.[a-zA-z0-9_-]{22}\.[a-zA-z0-9_-]{43}\b', "severity": "High"},
                {"name": "Mailgun API Key", "pattern": r'\bkey-[0-9a-zA-Z]{32}\b', "severity": "High", "context": r'(mailgun|mg)'},
                {"name": "Twilio API Key", "pattern": r'\bSK[a-f0-9]{32}\b', "severity": "High", "context": r'(twilio|auth_token)'},
                {"name": "NPM Token", "pattern": r'\bnpm_[A-Za-z0-9]{36}\b', "severity": "High"},
                {"name": "PyPI Token", "pattern": r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}', "severity": "High"},
                {"name": "Heroku API Key", "pattern": r'[hH][eE][rR][oO][kK][uU][a-zA-Z0-9]{20,}', "severity": "High"},
                {"name": "Mapbox Token", "pattern": r'\bpk\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\b', "severity": "High", "context": r'(mapbox|api\.mapbox)', "min_len": 20},
                {"name": "Square API Key", "pattern": r'\bsq0atp-[0-9A-Za-z_-]{22}\b', "severity": "High"},
                {"name": "Shopify API Key", "pattern": r'\bshpat_[a-f0-9]{32}\b', "severity": "High"},
                {"name": "PayPal API Key", "pattern": r'\bA20[A-Z0-9]{16}\b', "severity": "High"},
            ],
            
            # ========== 地图API密钥 ==========
            "map_keys": [
                {"name": "高德地图API Key", "pattern": r'\b[a-zA-Z0-9]{32}\b', "severity": "High", "context": r'(amap\.com|gaode\.com|AMap|高德|高德地图)', "min_len": 32},
                {"name": "百度地图API Key", "pattern": r'\bc[a-zA-Z0-9]{31,32}\b', "severity": "Medium", "context": r'(map\.baidu|bdmap|ak=|BMap|百度|baidumap|mapapi)', "min_len": 31},
                {"name": "腾讯地图API Key", "pattern": r'\bkey-[a-zA-Z0-9]{20,}\b', "severity": "Medium", "context": r'(lbs\.qq|tencent.*map|map\.qq|key\s*=)', "min_len": 25},
                {"name": "Google Maps API Key", "pattern": r'\bAIza[0-9A-Za-z_-]{35}\b', "severity": "Critical", "context": r'(maps\.googleapis|googleapis|google\.com/maps|gme\.)', "min_len": 35},
                {"name": "Here Maps API Key", "pattern": r'\bAP-[a-zA-Z0-9_-]{32,}\b', "severity": "High", "context": r'(api\.here\.com|heremaps|HERE|key\s*=)', "min_len": 32},
                {"name": "天地图API Key", "pattern": r'\b[a-zA-Z0-9]{32}\b', "severity": "Medium", "context": r'(tianditu\.gov|tianditu\.com|天地图)', "min_len": 32},
                {"name": "Mapbox Token", "pattern": r'\bpk\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b', "severity": "High", "context": r'(api\.mapbox|mapbox\.com)', "min_len": 20},
                {"name": "OpenStreetMap API Key", "pattern": r'\b[a-zA-Z0-9_-]{32}\b', "severity": "Low", "context": r'(nominatim\.openstreetmap|osm)', "min_len": 32},
                {"name": "TomTom Maps API Key", "pattern": r'\b[a-zA-Z0-9_-]{32}\b', "severity": "Medium", "context": r'(api\.tomtom\.com|tomtom)', "min_len": 32},
                {"name": "高德开放平台API", "pattern": r'\b[a-zA-Z0-9]{32}\b', "severity": "High", "context": r'(rest\.amap\.com|webapi\.amap)', "min_len": 32},
                {"name": "腾讯位置服务API", "pattern": r'\b[a-zA-Z0-9]{32}\b', "severity": "Medium", "context": r'(lbs\.qq\.com|apis\.map\.qq)', "min_len": 32},
            ],
            
            # ========== 认证令牌 ==========
            "auth_tokens": [
                {"name": "JWT Token", "pattern": r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+', "severity": "Critical"},
                {"name": "Bearer Token", "pattern": r'Bearer\s+[a-zA-Z0-9\-_\.=]+', "severity": "High"},
                {"name": "Basic Auth", "pattern": r'Basic\s+[a-zA-Z0-9+/=]+', "severity": "High"},
                {"name": "OAuth Token", "pattern": r'(?i)(access_token|refresh_token)[^\s]{0,30}([a-zA-Z0-9\-_\.=]{20,})', "severity": "High"},
                {"name": "API Key (Generic)", "pattern": r'(?i)(api[_-]?key|apikey)[^\s]{0,30}([a-zA-Z0-9]{16,})', "severity": "Medium"},
            ],
            
            # ========== 个人信息 (JSFinderPlus规则) ==========
            "personal_info": [
                {"name": "邮箱地址", "pattern": r'([a-zA-Z0-9][_|\.])*[a-zA-Z0-9]+@([a-zA-Z0-9][-|_|\.])*[a-zA-Z0-9]+\.((?!js|css|jpg|jpeg|png|ico)[a-zA-Z]{2,})', "severity": "Medium"},
                {"name": "中国手机号", "pattern": r'\b1[3-9]\d{9}\b', "severity": "High"},
                {"name": "中国身份证", "pattern": r'\b(?!000|999|0000|9999)\d{6}((0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]|\d{6}(18|19|20)\d{2}(0[1-9]|10|11|12)(0[1-9]|[12]\d|30|31)\d{3}[0-9Xx])\b', "severity": "Critical", "context": r'(身份证|idcard|ID|no|number|证件)', "min_len": 18},
                {"name": "银行卡号(银联)", "pattern": r'\b(?:62[0-9]{14,17}|88[0-9]{13,16})\b', "severity": "High"},
                {"name": "银行卡号(VISA)", "pattern": r'\b4[0-9]{12}(?:[0-9]{3})?\b', "severity": "High"},
                {"name": "银行卡号(Master)", "pattern": r'\b(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}\b', "severity": "High"},
                {"name": "IPv4内网地址", "pattern": r'(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})', "severity": "Low"},
                {"name": "IPv6地址", "pattern": r'([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}', "severity": "Low"},
            ],
            
            # ========== 硬编码凭证 (原版+增强) ==========
            "hardcoded_creds": [
                {"name": "硬编码密码", "pattern": r'(?i)(?:password|passwd|pwd|passphrase|secret)[^\s]{0,20}[=:]\s*["\']([^"\']{4,})["\']', "severity": "Critical"},
                {"name": "硬编码用户名", "pattern": r'(?i)(?:username|user|login[_-]?name)[^\s]{0,20}[=:]\s*["\']([^"\']{3,})["\']', "severity": "High"},
                {"name": "硬编码API密钥", "pattern": r'(?i)(?:api[_-]?key|api[_-]?secret|app[_-]?key|app[_-]?secret|access[_-]?token)[^\s]{0,30}[=:]\s*["\']([^"\']{8,})["\']', "severity": "Critical"},
                {"name": "数据库连接", "pattern": r'(?i)(?:mysql|postgres|mongodb|redis|sqlserver|oracle)[^\s]{0,50}(?:user|uid|pwd|pass|password)[^\s]{0,20}[=:][^\s]{0,20}["\']?([^\s"\']{4,})', "severity": "Critical"},
                {"name": "SSH私钥", "pattern": r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|ED25519)\s+PRIVATE\s+KEY-----', "severity": "Critical"},
                {"name": "AWS凭证", "pattern": r'(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)[^\s]{0,30}[=:]\s*["\']([^"\']{16,})["\']', "severity": "Critical"},
                {"name": "JWT密钥", "pattern": r'(?i)(jwt[_-]?secret|jwt[_-]?key|json[_-]?web[_-]?token[_-]?secret)[^\s]{0,30}[=:]\s*["\']([^"\']{16,})["\']', "severity": "High"},
                {"name": "加密密钥", "pattern": r'(?i)(encryption[_-]?key|aes[_-]?key|cipher[_-]?key|secret[_-]?key)[^\s]{0,30}[=:]\s*["\']([^"\']{8,})["\']', "severity": "High"},
                {"name": "Firebase配置", "pattern": r'(?i)(firebase)[^\s]{0,30}\{[^}]{10,200}\}', "severity": "High"},
                {"name": "多行硬编码密码", "pattern": r'(?i)(?:password|passwd|pwd|secret)[^\s]{0,20}[=:]\s*(?:"""(.{4,})"""|\'\'\'(.{4,})\'\'\')', "severity": "Critical"},
                {"name": "多行硬编码API密钥", "pattern": r'(?i)(?:api[_-]?key|api[_-]?secret|app[_-]?key|app[_-]?secret)[^\s]{0,30}[=:]\s*(?:"""(.{8,})"""|\'\'\'(.{8,})\'\'\')', "severity": "Critical"},
                {"name": "多行数据库凭证", "pattern": r'(?i)(?:db[_-]?user|db[_-]?pass|database[_-]?username|database[_-]?password)[^\s]{0,30}[=:]\s*(?:"""(.{4,})"""|\'\'\'(.{4,})\'\'\')', "severity": "Critical"},
                {"name": "多行加密密钥", "pattern": r'(?i)(?:encryption[_-]?key|aes[_-]?key|jwt[_-]?secret)[^\s]{0,30}[=:]\s*(?:"""(.{8,})"""|\'\'\'(.{8,})\'\'\')', "severity": "High"},
                {"name": "多行AWS凭证", "pattern": r'(?i)(?:aws[_-]?access[_-]?key|aws[_-]?secret)[^\s]{0,30}[=:]\s*(?:"""(.{16,})"""|\'\'\'(.{16,})\'\'\')', "severity": "Critical"},
                {"name": "多行Google凭证", "pattern": r'(?i)(?:google[_-]?application[_-]?credentials|google[_-]?api[_-]?key)[^\s]{0,30}[=:]\s*(?:"""[^\s]{10,}"""|\'\'\'[^\s]{10,}\'\'\')', "severity": "Critical"},
            ],
            
            # ========== 敏感路径/文件 (仅URL路径检测) ==========
            "sensitive_paths": [
                {"name": "Git泄露", "pattern": r'(?i)\.git/(?:HEAD|config|index|objects)', "severity": "Critical", "target": "url"},
                {"name": "SVN泄露", "pattern": r'(?i)\.svn/(?:entries|wc\.db)', "severity": "High", "target": "url"},
                {"name": "DS_Store", "pattern": r'(?i)\.DS_Store', "severity": "Medium", "target": "url"},
                {"name": "环境变量文件", "pattern": r'(?i)\.env(?:\.local|\.dev|\.prod)?', "severity": "Critical", "target": "url"},
                {"name": "配置文件", "pattern": r'(?i)(?:^|/)(?:config|settings)\.(?:json|yaml|yml|xml|ini|conf)$', "severity": "High", "target": "url"},
                {"name": "备份文件", "pattern": r'(?i)(?:^|/)\.(?:bak|backup|old)$', "severity": "Medium", "target": "url"},
                {"name": "源代码压缩包", "pattern": r'(?i)\.(?:tar\.gz|zip|rar|7z|tar)(?:\?|$)', "severity": "High", "target": "url"},
                {"name": "Spring Boot Actuator", "pattern": r'(?i)/actuator(?:/|$)', "severity": "High", "target": "url"},
                {"name": "Spring Boot全端点", "pattern": r'(?i)/(?:env|beans|configprops|mappings|health|info|heapdump|threaddump)', "severity": "High", "target": "url"},
                {"name": "Swagger UI", "pattern": r'(?i)/(?:swagger|swagger-ui|api-docs|v2/api-docs|openapi)', "severity": "Medium", "target": "url"},
                {"name": "Druid监控", "pattern": r'(?i)/druid/(?:index|login|websession|sql)\.html', "severity": "High", "target": "url"},
                {"name": "Jenkins", "pattern": r'(?i)/(?:jenkins|script|manage)/', "severity": "Critical", "target": "url"},
                {"name": "PHPMyAdmin", "pattern": r'(?i)/(?:phpmyadmin|pma)/', "severity": "Critical", "target": "url"},
                {"name": "Redis未授权", "pattern": r'(?i)/(?:redis|redistogo)/', "severity": "High", "target": "url"},
                {"name": "Elasticsearch", "pattern": r'(?i)/(?:_cat|_cluster|_nodes|_search|/_shield)', "severity": "High", "target": "url"},
                {"name": "Kibana", "pattern": r'(?i)/app/kibana|/api/console', "severity": "High", "target": "url"},
                {"name": "Consul", "pattern": r'(?i)/v1/(?:agent|catalog|health|kv)', "severity": "High", "target": "url"},
            ],
            
            # ========== 框架特征 ==========
            "framework_signs": [
                {"name": "Vue.js调试", "pattern": r'(?i)vuejs\.org|__VUE_DEVTOOLS_PLUGIN__', "severity": "Medium"},
                {"name": "React调试", "pattern": r'(?i)reactjs\.org|__REACT_DEVTOOLS', "severity": "Medium"},
                {"name": "Angular调试", "pattern": r'(?i)angular\.io|ng-inspector', "severity": "Medium"},
                {"name": "Sourcemap泄露", "pattern": r'(?i)//#\s*sourceMappingURL=', "severity": "Critical"},
                {"name": "StackTrace泄露", "pattern": r'(?i)at\s+(?:new\s+)?(?:\w+\.)+\w+\s*\(?(?:\w+:)?\d+:\d+\)?', "severity": "Medium"},
                {"name": "调试模式开启", "pattern": r'(?i)(?:debug[_-]?mode|dev[_-]?mode|application[_-]?debug)\s*[=:]\s*(?:true|1|yes)', "severity": "High"},
            ]
        }

    def _init_endpoint_patterns(self) -> List[Dict]:
        return [
            {"pattern": r"fetch\s*\(\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"fetch\s*\(\s*\{[^}]*url:\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"axios\.get\s*\(\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"axios\.post\s*\(\s*['\"]([^'\"]+)['\"]", "method": "POST", "group": 1},
            {"pattern": r"axios\.put\s*\(\s*['\"]([^'\"]+)['\"]", "method": "PUT", "group": 1},
            {"pattern": r"axios\.delete\s*\(\s*['\"]([^'\"]+)['\"]", "method": "DELETE", "group": 1},
            {"pattern": r"axios\.create\s*\(\s*\{[^}]*baseURL:\s*['\"]([^'\"]+)['\"]", "method": "BASE", "group": 1},
            {"pattern": r"axios\([^)]*\)\s*\.get\s*\(\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"axios\([^)]*\)\s*\.post\s*\(\s*['\"]([^'\"]+)['\"]", "method": "POST", "group": 1},
            {"pattern": r"\$\.get\s*\(\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"\$\.post\s*\(\s*['\"]([^'\"]+)['\"]", "method": "POST", "group": 1},
            {"pattern": r"\$\.ajax\s*\(\s*\{[^}]*url:\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"\$\.ajax\s*\(\s*\{[^}]*type:\s*['\"]GET['\"][^}]*url:\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"\$\.ajax\s*\(\s*\{[^}]*type:\s*['\"]POST['\"][^}]*url:\s*['\"]([^'\"]+)['\"]", "method": "POST", "group": 1},
            {"pattern": r"XMLHttpRequest.*\.open\s*\(\s*['\"](GET|POST|PUT|DELETE)['\"]\s*,\s*['\"]([^'\"]+)['\"]", "method": "group", "group": 2, "method_group": 1},
            {"pattern": r"new\s+URL\s*\(\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"(?:GET|POST|PUT|DELETE|OPTIONS|PATCH)\s+['\"](/api[\w\-\.\/]*)['\"]", "method": "GET", "group": 1},
            {"pattern": r"['\"]\/api\/v\d+[\w\-\.\/]*['\"]", "method": "GET", "group": 0},
            {"pattern": r"router\.(?:get|post|put|delete|add)\s*\(\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"route:\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"path:\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"location\.href\s*=\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"action\s*=\s*['\"]([^'\"]+)['\"]", "method": "POST", "group": 1},
            {"pattern": r"(?:goTo|redirectTo|navigateTo|push|replace)\s*\(\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"WebSocket\s*\(\s*['\"]([^'\"]+)['\"]", "method": "WS", "group": 1},
            {"pattern": r"apiUrl\s*[:=]\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"apiHost\s*[:=]\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"baseURL\s*[:=]\s*['\"]([^'\"]+)['\"]", "method": "BASE", "group": 1},
            {"pattern": r"data\s*[:=]\s*\{[^}]*url:\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"method:\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"][^}]*url:\s*['\"]([^'\"]+)['\"]", "method": "group", "group": 2, "method_group": 1},
            {"pattern": r"service\s*\([^)]*\)\s*\.\s*(?:get|post|put|delete)\s*\(\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"Vue\.axios\.[get|post|put|delete]\s*\(\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"wx\.request\s*\(\s*\{[^}]*url:\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"request\s*\(\s*\{[^}]*url:\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"http\.request\s*\(\s*\{[^}]*url:\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"import\s+.*\s+from\s+['\"][^'\"]*api[^'\"]*['\"]", "method": "IMPORT", "group": 0},
            {"pattern": r"require\s*\(\s*['\"][^'\"]*api[^'\"]*['\"]", "method": "IMPORT", "group": 0},
            {"pattern": r"@RequestMapping\s*\(\s*value\s*=\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"@GetMapping\s*\(\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"@PostMapping\s*\(\s*['\"]([^'\"]+)['\"]", "method": "POST", "group": 1},
            {"pattern": r"@PutMapping\s*\(\s*['\"]([^'\"]+)['\"]", "method": "PUT", "group": 1},
            {"pattern": r"@DeleteMapping\s*\(\s*['\"]([^'\"]+)['\"]", "method": "DELETE", "group": 1},
            {"pattern": r"@ApiOperation\s*\(\s*['\"][^'\"]*['\"]\s*\)\s*public\s+\w+\s+(\w+)\s*\(", "method": "API", "group": 1},
            {"pattern": r"router\s*\(\s*\{\s*path:\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"Routes\s*\[\s*\{[^{]*path:\s*['\"]([^'\"]+)['\"]", "method": "GET", "group": 1},
            {"pattern": r"url\s*:\s*['\"]([^'\"]*(?:api|API|endpoint|Endpoint|admin|Admin|user|User|order|Order|data|Data|file|File|upload|Upload)[^'\"]*)['\"]", "method": "GET", "group": 1},
            {"pattern": r"['\"]/(api|v1|v2|v3|rest|graphql|query|search|list|get|post|update|delete|add|edit|save|load|fetch|data|info|detail|config|setting|user|admin|member|order|product|file|upload|download|export|import|login|logout|register|auth|token|session)[\w\-\.\/]*['\"]", "method": "GET", "group": 0},
            {"pattern": r"['\"]https?://[^'\"]+/[\w\-\.\/]+['\"]", "method": "GET", "group": 0},
            {"pattern": r"src\s*=\s*['\"]([^'\"]+\.js[^'\"]*)['\"]", "method": "JS", "group": 1},
            {"pattern": r"href\s*=\s*['\"]([^'\"]+\.(?:css|html|php|asp|jsp)[^'\"]*)['\"]", "method": "STATIC", "group": 1},
            {"pattern": r"['\"]\.?\.?\/[\w\-\.\/]+\.(?:js|css|html|json|xml|txt)['\"]", "method": "RELATIVE", "group": 0},
            {"pattern": r"import\s*\(\s*['\"]([^'\"]+)['\"]", "method": "IMPORT", "group": 1},
            {"pattern": r"define\s*\(\s*\[([^\]]+)\]", "method": "DEFINE", "group": 1},
            {"pattern": r"require\.ensure\s*\(\s*\[([^\]]+)\]", "method": "REQUIRE", "group": 1},
            {"pattern": r"chunkFilename\s*:\s*['\"]([^'\"]+)['\"]", "method": "CHUNK", "group": 1},
            {"pattern": r"publicPath\s*:\s*['\"]([^'\"]+)['\"]", "method": "PUBLIC", "group": 1},
            {"pattern": r"outputPath\s*:\s*['\"]([^'\"]+)['\"]", "method": "OUTPUT", "group": 1},
            {"pattern": r"assetsPublicPath\s*:\s*['\"]([^'\"]+)['\"]", "method": "ASSETS", "group": 1},
            {"pattern": r"staticPath\s*[:=]\s*['\"]([^'\"]+)['\"]", "method": "STATIC", "group": 1},
            {"pattern": r"assetPath\s*[:=]\s*['\"]([^'\"]+)['\"]", "method": "ASSET", "group": 1},
            {"pattern": r"template\s*:\s*['\"]([^'\"]+\.html[^'\"]*)['\"]", "method": "TEMPLATE", "group": 1},
            {"pattern": r"component\s*:\s*\(\s*\)\s*=>\s*import\s*\(\s*['\"]([^'\"]+)['\"]", "method": "COMPONENT", "group": 1},
            {"pattern": r"loaders?\s*:\s*\[([^\]]+)\]", "method": "LOADER", "group": 1},
            {"pattern": r"plugins?\s*:\s*\[([^\]]+)\]", "method": "PLUGIN", "group": 1},
            {"pattern": r"entry\s*:\s*\{[^}]+\}", "method": "ENTRY", "group": 0},
            {"pattern": r"['\"`](?:(?:\.\.?\/)[^'\"<>\s]+)['\"`]", "method": "GET", "group": 0},
            {"pattern": r"['\"`](?:(?:\/)[^'\"<>\s]+)['\"`]", "method": "GET", "group": 0},
            {"pattern": r"['\"`](?:(?:\/)(?:api|API|v1|v2|v3|admin|user|data|login|auth|token|file|upload|download|config|setting|module|router|route|path)[\w\-\.\/]*)['\"`]", "method": "GET", "group": 0},
            {"pattern": r"['\"`](?:(?:\.\.?\/)(?:api|API|v1|v2|v3|admin|user|data|login|auth|token|file|upload|download|config|setting|module|router|route|path|component|view|page|layout|service|store)[\w\-\.\/]*)['\"`]", "method": "RELATIVE", "group": 0},
            {"pattern": r"['\"`](?:(?:\/)(?:api|API|v1|v2|v3|admin|user|data|login|auth|token|file|upload|download|config|setting|module|router|route|path|component|view|page|layout|service|store)[\w\-\.\/]*)['\"`]", "method": "ABSOLUTE", "group": 0},
            {"pattern": r"import\s+.*?\s+from\s+['\"]([^'\"]+\.js)['\"]", "method": "IMPORT", "group": 1},
            {"pattern": r"import\s*\(\s*['\"]([^'\"]+\.js)['\"]", "method": "IMPORT", "group": 1},
            {"pattern": r"require\s*\(\s*['\"]([^'\"]+\.js)['\"]", "method": "IMPORT", "group": 1},
        ]

    def _init_vulnerable_libs(self) -> Dict:
        return {
            "jquery": {"min_safe": "3.5.0", "cves": ["CVE-2020-11022", "CVE-2020-11023", "CVE-2019-11358"]},
            "jquery-ui": {"min_safe": "1.13.0", "cves": ["CVE-2021-44906"]},
            "bootstrap": {"min_safe": "4.4.0", "cves": ["CVE-2019-8331", "CVE-2018-14041"]},
            "lodash": {"min_safe": "4.17.21", "cves": ["CVE-2021-23337", "CVE-2019-10192"]},
            "moment": {"min_safe": "2.29.4", "cves": ["CVE-2022-24785", "CVE-2022-31129"]},
            "axios": {"min_safe": "1.6.0", "cves": ["CVE-2023-45857", "CVE-2022-31137"]},
            "vue": {"min_safe": "3.0.0", "cves": []},
            "react": {"min_safe": "18.2.0", "cves": ["CVE-2022-1097"]},
            "angular": {"min_safe": "15.0.0", "cves": []},
            "serialize-javascript": {"min_safe": "3.1.0", "cves": ["CVE-2020-7660"]},
            "glob-parent": {"min_safe": "5.1.2", "cves": ["CVE-2020-28469"]},
            "minimist": {"min_safe": "1.2.8", "cves": ["CVE-2021-44906"]},
            "node-fetch": {"min_safe": "2.6.13", "cves": ["CVE-2022-0235"]},
            "ua-parser-js": {"min_safe": "0.7.33", "cves": ["CVE-2022-25927", "CVE-2022-25887"]},
            "tar": {"min_safe": "6.2.1", "cves": ["CVE-2021-37701", "CVE-2021-44906"]},
            "glob": {"min_safe": "7.2.3", "cves": ["CVE-2021-35065"]},
            "nth-check": {"min_safe": "2.0.2", "cves": ["CVE-2021-3803"]},
            "postcss": {"min_safe": "8.4.31", "cves": ["CVE-2023-44270", "CVE-2023-45723"]},
            "semver": {"min_safe": "7.5.4", "cves": ["CVE-2022-25883"]},
            "word-wrap": {"min_safe": "1.2.6", "cves": ["CVE-2023-26115"]},
            "shell-quote": {"min_safe": "1.7.3", "cves": ["CVE-2021-42740"]},
            "json5": {"min_safe": "1.0.2", "cves": ["CVE-2022-46175"]},
        }

    def _init_dangerous_functions(self) -> Dict:
        return {
            "XSS": {
                "sinks": ["innerHTML", "outerHTML", "document.write", "insertAdjacentHTML", "eval", "Function", "setTimeout", "setInterval", "execScript"],
                "sources": ["location.hash", "location.search", "document.URL", "document.documentURI", "document.referrer", "window.name", "localStorage.getItem", "sessionStorage.getItem", "URLSearchParams.get"]
            },
            "CodeInjection": {
                "sinks": ["eval", "Function", "exec", "execScript", "setTimeout", "setInterval", "setImmediate"],
                "sources": ["location", "document.cookie", "localStorage", "sessionStorage", "document.domain"]
            },
            "PrototypePollution": {
                "sinks": ["__proto__", "constructor.prototype", "__defineGetter__", "__defineSetter__"],
                "sources": ["Object.assign", "Object.create", "Object.setPrototypeOf", "$.extend", "_.merge", "_.defaultsDeep", "jQuery.extend"]
            },
            "URLRedirect": {
                "sinks": ["location.href", "location.replace", "location.assign", "window.location", "meta.refresh"],
                "sources": ["location.search", "location.hash", "URLSearchParams", "document.referrer"]
            }
        }
    
    def _init_vuln_tester(self):
        self.SQLI_ERRORS = [
            "mysql_fetch", "mysql_num_rows", "sql syntax", "mysql error",
            "sqlsrv", "odbc_", "unterminated", "microsoft sql",
            "postgresql", "pg_fetch", "sqlite3", "sql error",
            "ora-", "oracle", "disallowed", "fatal error"
        ]
        
        self.XSS_PAYLOADS = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
        ]
        
        self.LFI_PATHS = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "/etc/passwd",
        ]
        
        self.RCE_PAYLOADS = [
            ";ls",
            "|ls",
            "&ls",
            "`ls`",
            "$(ls)",
        ]
    
    def _init_header_pool(self) -> List[Dict]:
        """初始化HTTP头轮换池 - 模拟真实浏览器"""
        return [
            {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"Windows"',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
            },
            {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
                'Accept-Encoding': 'gzip, deflate, br',
                'Sec-Ch-Ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"macOS"',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
            },
            {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                'Accept-Encoding': 'gzip, deflate, br',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
            },
            {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh-Hans;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
            },
        ]
    
    def rotate_headers(self) -> Dict:
        """轮换HTTP头 - 模拟不同浏览器"""
        if self.header_rotation_pool:
            new_headers = random.choice(self.header_rotation_pool).copy()
            new_headers['Referer'] = self.target_url
            self.current_headers = new_headers
            return new_headers
        return self.headers.copy()
    
    def extract_csrf_token(self, content: str, url: str = "") -> Optional[str]:
        """从页面内容中提取CSRF Token"""
        for pattern in self.csrf_token_patterns:
            matches = re.findall(pattern, content, re.I)
            if matches:
                # 提取token值
                token = matches[0]
                if isinstance(token, tuple):
                    token = token[-1]  # 取最后一个分组
                if url:
                    self.csrf_tokens[url] = token
                return token
        return None
    
    def get_csrf_headers(self, url: str = "") -> Dict[str, str]:
        """获取包含CSRF Token的请求头"""
        headers = {}
        
        # 检查是否有X-CSRF-Token头
        if url and url in self.csrf_tokens:
            headers['X-CSRF-Token'] = self.csrf_tokens[url]
            headers['X-Requested-With'] = 'XMLHttpRequest'
        
        return headers
    
    def save_cookies(self, filepath: str = None):
        """保存Cookie到文件"""
        if filepath:
            self.cookie_jar_file = filepath
        
        if self.cookie_jar_file:
            try:
                cookies_dict = {}
                for cookie in self.session.cookies:
                    cookies_dict[cookie.name] = {
                        'value': cookie.value,
                        'domain': cookie.domain,
                        'path': cookie.path,
                    }
                with open(self.cookie_jar_file, 'w') as f:
                    json.dump(cookies_dict, f)
                logger.debug(f"Cookie已保存到: {self.cookie_jar_file}")
            except Exception as e:
                logger.debug(f"保存Cookie失败: {e}")
    
    def load_cookies(self, filepath: str = None) -> bool:
        """从文件加载Cookie"""
        if filepath:
            self.cookie_jar_file = filepath
        
        if self.cookie_jar_file and os.path.exists(self.cookie_jar_file):
            try:
                with open(self.cookie_jar_file, 'r') as f:
                    cookies_dict = json.load(f)
                
                for name, cookie_data in cookies_dict.items():
                    self.session.cookies.set(
                        name, 
                        cookie_data.get('value', ''),
                        domain=cookie_data.get('domain', ''),
                        path=cookie_data.get('path', '/')
                    )
                logger.info(f"{Colors.GREEN}[+] 已加载Cookie: {self.cookie_jar_file}{Colors.END}")
                return True
            except Exception as e:
                logger.debug(f"加载Cookie失败: {e}")
        return False
    
    def update_rate_limit_stats(self, response_time: float, status_code: int):
        """更新速率限制统计"""
        if not self.adaptive_rate_limit:
            return
        
        # 记录请求时间
        self.request_times.append(response_time)
        if len(self.request_times) > 20:  # 只保留最近20个
            self.request_times.pop(0)
        
        # 更新统计
        if status_code in [429, 503, 502]:
            self.rate_limit_stats['error_count'] += 1
        else:
            self.rate_limit_stats['success_count'] += 1
        
        # 计算平均响应时间
        if self.request_times:
            self.rate_limit_stats['avg_response_time'] = sum(self.request_times) / len(self.request_times)
        
        # 动态调整延迟
        if self.rate_limit_stats['error_count'] > 3:
            # 错误过多，增加延迟
            self.rate_limit_stats['current_delay'] = min(self.rate_limit_stats['current_delay'] + 0.5, 5.0)
            self.rate_limit_stats['error_count'] = 0
            logger.debug(f"增加请求延迟至: {self.rate_limit_stats['current_delay']:.1f}s")
        elif self.rate_limit_stats['success_count'] > 10 and self.rate_limit_stats['current_delay'] > 0:
            # 成功率高，可以减少延迟
            self.rate_limit_stats['current_delay'] = max(self.rate_limit_stats['current_delay'] - 0.1, 0)
            self.rate_limit_stats['success_count'] = 0
    
    def adaptive_delay(self):
        """自适应延迟"""
        if self.adaptive_rate_limit and self.rate_limit_stats['current_delay'] > 0:
            time.sleep(self.rate_limit_stats['current_delay'])
        elif self.request_delay > 0:
            time.sleep(self.request_delay)
    
    def _init_waf_modules(self):
        self.WAF_SIGNATURES = {
            # 国际WAF
            "Cloudflare": ["cf-ray", "__cfduid", "cloudflare", "CF-Cache-Status"],
            "AWS WAF": ["awselb", "X-Amzn-Trace-Id", "aws-waf"],
            "Akamai": ["akamai", "AkamaiGHost", "X-Akamai"],
            "Sucuri": ["sucuri", "SucuriWebsiteSecurity", "X-Sucuri"],
            "Incapsula": ["incap_id", "visid_incap", "X-Incapsula"],
            "ModSecurity": ["ModSecurity", "NocdWatcher", "mod_security"],
            "F5 BIG-IP": ["F5", "BIG-IP", "X-WA-Info"],
            "Imperva": ["imperva", "X-Iinfo", "Incapsula"],
            "Barracuda": ["barra", "X-Barracuda"],
            "Citrix": ["citrix", "X-Citrix"],
            "Fortinet": ["fortinet", "X-Fortinet"],
            "Palo Alto": ["paloalto", "X-PaloAlto"],
            "Radware": ["radware", "X-Radware"],
            "Sophos": ["sophos", "X-Sophos"],
            "Wordfence": ["wordfence", "X-WF"],
            "SiteGround": ["siteground", "X-SiteGround"],
            
            # 国产WAF
            "阿里云盾": ["aliyun", "alicdn", "x-alicdn", "aliyungf_tc", "yunjiasu"],
            "腾讯云WAF": ["tencent", "qcloud", "x-qcloud", "tencentwaf", "x-waf-tencent"],
            "华为云WAF": ["huaweicloud", "hwcloud", "x-hw", "huaweiwaf"],
            "百度云加速": ["yunjiasu", "baiduyun", "x-bce", "baiduwap"],
            "安全狗": ["safedog", "safedog-site", "x-safedog", "waf/2.0", "safedog-flow"],
            "云锁": ["yunsuo", "yunsuo-session", "x-yunsuo", "yunsuo-waf"],
            "360网站卫士": ["360wzb", "360waf", "x-360waf", "360wzws", "360safe"],
            "知道创宇云安全": ["zhidaochuangyu", "yunaq", "x-yunaq", "knowsec"],
            "安恒明鉴": ["dbappwaf", "dbappsecurity", "x-dbapp", "dbapp-waf"],
            "长亭雷池": ["chaitin", "safeline", "x-chaitin", "safeline-waf"],
            "F5中国": ["f5-china", "f5-waf-cn", "x-f5-cn"],
            "网宿云WAF": ["wangsu", "chinacache", "x-wangsu", "wangsuwaf"],
            "又拍云WAF": ["upyun", "x-upyun", "upyun-waf"],
            "七牛云WAF": ["qiniu", "x-qiniu", "qiniu-waf"],
            "UCloud优刻得": ["ucloud", "x-ucloud", "ucloud-waf"],
            "青云WAF": ["qingcloud", "x-qingcloud", "qingcloud-waf"],
            "京东云星盾": ["jdcloud", "x-jdcloud", "jdcloud-waf", "starshield"],
            "网神WAF": ["legendsec", "x-legendsec", "legendsec-waf"],
            "绿盟WAF": ["nsfocus", "x-nsfocus", "nsfocus-waf"],
            "启明星辰天清": ["venustech", "x-venustech", "venustech-waf"],
            "深信服AD": ["sangfor", "x-sangfor", "sangfor-waf"],
            "迪普科技": ["dptech", "x-dptech", "dptech-waf"],
            "山石网科": ["hillstone", "x-hillstone", "hillstone-waf"],
            "天融信": ["topsec", "x-topsec", "topsec-waf"],
        }
        
        # WAF绕过Payload字典
        self.WAF_BYPASS_TECHNIQUES = {
            "sqli": {
                "comment_obfuscation": [
                    "'/**/OR/**/1=1",
                    "'/*!50000OR*/1=1",
                    "' OR--\n1=1",
                    "' OR#\n1=1",
                    "' OR/*comment*/1=1",
                ],
                "encoding": [
                    "%27%20OR%20%271%27%3D%271",
                    "%2527%2520OR%2520%25271%2527%253D%25271",
                    "'\x4f\x52\x20'1'='1",
                ],
                "case_variation": [
                    "' Or '1'='1",
                    "' oR '1'='1",
                    "' OR '1'='1",
                ],
                "whitespace_alternatives": [
                    "'OR(1=1)",
                    "'OR(1=1)--",
                    "'OR'1'='1",
                ],
                "union_bypass": [
                    "' UNION/**/SELECT/**/null--",
                    "'/*!50000UNION*//*!50000SELECT*/null--",
                ],
            },
            "xss": {
                "encoding": [
                    "%3Cscript%3Ealert(1)%3C/script%3E",
                    "%253Cscript%253Ealert(1)%253C/script%253E",
                    "&#60;script&#62;alert(1)&#60;/script&#62;",
                    "&lt;script&gt;alert(1)&lt;/script&gt;",
                ],
                "case_variation": [
                    "<ScRiPt>alert(1)</ScRiPt>",
                    "<sCrIpT>alert(1)</ScRiPt>",
                ],
                "alternative_tags": [
                    "<img src=x onerror=alert(1)>",
                    "<svg onload=alert(1)>",
                    "<body onload=alert(1)>",
                    "<iframe src=javascript:alert(1)>",
                    "<input onfocus=alert(1) autofocus>",
                ],
                "obfuscation": [
                    "<script>alert(String.fromCharCode(49))</script>",
                    "<script>eval(atob('YWxlcnQoMSk='))</script>",
                    "<script>top['al'+'ert'](1)</script>",
                ],
                "polyglots": [
                    "'\"><svg/onload=alert(1)>",
                    "javascript:alert(1)",
                    "'\"><img src=x onerror=alert(1)>",
                ],
            },
            "lfi": {
                "encoding": [
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                    "....//....//....//etc/passwd",
                ],
                "null_byte": [
                    "%00/etc/passwd",
                    "%00../../etc/passwd",
                ],
                "double_encoding": [
                    "%252e%252e%252fetc%252fpasswd",
                    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                ],
            },
            "rce": {
                "encoding": [
                    "$(printf '%s' 'id')",
                    "`printf '%s' 'id'`",
                    "$(printf '%s' $(echo 'id'))",
                ],
                "bypass_filters": [
                    r"i\d",
                    "i''d",
                    "i${IFS}d",
                    "cat${IFS}/etc/passwd",
                ],
            },
        }
        
        # HTTP请求绕过技术
        self.HTTP_BYPASS_TECHNIQUES = {
            "headers": {
                "X-Forwarded-For": ["127.0.0.1", "::1", "10.0.0.1", "192.168.1.1"],
                "X-Real-IP": ["127.0.0.1", "::1"],
                "X-Originating-IP": ["127.0.0.1"],
                "X-Remote-IP": ["127.0.0.1"],
                "X-Client-IP": ["127.0.0.1"],
                "X-Remote-Addr": ["127.0.0.1"],
                "X-Forwarded-Host": ["localhost", "127.0.0.1"],
                "X-Original-URL": ["/admin", "/api"],
                "X-Rewrite-URL": ["/admin", "/api"],
                "X-HTTP-Method-Override": ["PUT", "DELETE", "PATCH"],
                "User-Agent": [
                    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
                ],
            },
            "chunked_transfer": True,
            "path_encoding": [
                lambda p: p.replace("../", "%2e%2e%2f"),
                lambda p: p.replace("../", "%252e%252e%252f"),
                lambda p: p.replace("/", "%2f"),
                lambda p: p.replace("/", "%252f"),
            ],
        }
        
        # WAF检测状态
        self.waf_detected = False
        self.waf_type = None
        self.waf_bypass_mode = False
        self.request_delay = 0  # 请求延迟（秒）
    
    def _init_fingerprint_modules(self):
        """初始化指纹识别模块"""
        self.fingerprint_results: List[FingerprintResult] = []
        self.api_doc_parser = APIDocParser(self.session)
        self.parsed_api_docs: List[ParsedAPIDoc] = []
        self.api_doc_endpoints: List[APIEndpoint] = []

    def detect_waf(self, headers: Dict, body: str = "") -> Optional[str]:
        """检测WAF类型并启用绕过模式"""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in headers_lower or sig.lower() in body.lower():
                    if not self.waf_detected:
                        self.waf_detected = True
                        self.waf_type = waf_name
                        self.waf_bypass_mode = True
                        self.request_delay = 2  # 检测到WAF后增加延迟
                        logger.warning(f"{Colors.RED}[!] 检测到WAF: {waf_name}，启用绕过模式{Colors.END}")
                        logger.info(f"{Colors.YELLOW}[*] 请求延迟调整为 {self.request_delay} 秒{Colors.END}")
                    return waf_name
        return None
    
    def get_bypass_headers(self) -> Dict[str, str]:
        """获取WAF绕过HTTP头"""
        bypass_headers = {}
        
        if not self.waf_bypass_mode:
            return bypass_headers
        
        # 随机选择一个X-Forwarded-For IP
        xff_ips = self.HTTP_BYPASS_TECHNIQUES["headers"].get("X-Forwarded-For", ["127.0.0.1"])
        bypass_headers["X-Forwarded-For"] = random.choice(xff_ips)
        bypass_headers["X-Real-IP"] = random.choice(xff_ips)
        
        # 随机选择User-Agent（搜索引擎爬虫）
        user_agents = self.HTTP_BYPASS_TECHNIQUES["headers"].get("User-Agent", [])
        if user_agents and random.random() > 0.5:
            bypass_headers["User-Agent"] = random.choice(user_agents)
        
        return bypass_headers
    
    def get_bypass_payloads(self, vuln_type: str) -> List[str]:
        """获取WAF绕过Payload"""
        if not self.waf_bypass_mode or vuln_type not in self.WAF_BYPASS_TECHNIQUES:
            return []
        
        payloads = []
        techniques = self.WAF_BYPASS_TECHNIQUES[vuln_type]
        
        # 从每种技术中选择一些payload
        for technique, technique_payloads in techniques.items():
            if technique_payloads:
                payloads.extend(random.sample(technique_payloads, min(2, len(technique_payloads))))
        
        return payloads
    
    def make_bypass_request(self, url: str, method: str = "GET",
                           data: Dict = None, params: Dict = None,
                           additional_headers: Dict = None,
                           use_header_rotation: bool = True) -> Optional[requests.Response]:
        """
        发送带有WAF绕过的HTTP请求
        支持：自适应延迟、Header轮换、CSRF Token、Cookie持久化
        """
        # 自适应延迟
        self.adaptive_delay()

        # 构建请求头
        if use_header_rotation and random.random() > 0.3:  # 70%概率轮换Header
            headers = self.rotate_headers().copy()
        else:
            headers = self.headers.copy()

        # 添加绕过头
        if self.waf_bypass_mode:
            bypass_headers = self.get_bypass_headers()
            headers.update(bypass_headers)

        # 添加CSRF Token
        csrf_headers = self.get_csrf_headers(url)
        if csrf_headers:
            headers.update(csrf_headers)

        # 添加额外头
        if additional_headers:
            headers.update(additional_headers)

        start_time = time.time()
        try:
            if method.upper() == "POST":
                resp = self.session.post(url, data=data, headers=headers,
                                        timeout=self.timeout, verify=False)
            else:
                resp = self.session.get(url, params=params, headers=headers,
                                       timeout=self.timeout, verify=False)

            # 更新速率限制统计
            response_time = time.time() - start_time
            self.update_rate_limit_stats(response_time, resp.status_code)

            # 提取CSRF Token
            if resp.status_code == 200:
                self.extract_csrf_token(resp.text, url)

            # 检查是否被WAF拦截
            if resp.status_code in [403, 406, 429, 503]:
                waf_detected = self.detect_waf(resp.headers, resp.text)
                if waf_detected:
                    logger.debug(f"请求被WAF拦截: {url}")
                    return None

            return resp
        except Exception as e:
            logger.debug(f"请求失败: {url} - {e}")
            return None
    
    def fingerprint_target(self, url: str, headers: Dict, content: str, cookies: Dict = None) -> List[FingerprintResult]:
        """
        对目标进行指纹识别（使用增强版）
        
        Args:
            url: 目标URL
            headers: HTTP响应头
            content: 响应内容
            cookies: Cookie信息
            
        Returns:
            指纹结果列表
        """
        logger.info(f"{Colors.CYAN}[*] 开始指纹识别（加权评分引擎）...{Colors.END}")
        
        # 使用新的指纹识别引擎（加权评分机制）
        engine = FingerprintEngine(self.session)
        
        # 获取页面标题
        title = ""
        if '<title>' in content.lower():
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(content, 'html.parser')
                title_tag = soup.find('title')
                if title_tag:
                    title = title_tag.get_text(strip=True)
            except:
                pass
        
        # 执行指纹识别
        new_results = engine.analyze(url, headers, content, title)
        
        # 添加到现有结果中
        self.fingerprint_results.extend(new_results)
        
        # 去重：保留置信度最高的
        seen = {}
        for fp in self.fingerprint_results:
            if fp.name not in seen or seen[fp.name].confidence < fp.confidence:
                seen[fp.name] = fp
        self.fingerprint_results = list(seen.values())
        
        # 显示指纹识别结果
        if self.fingerprint_results:
            logger.info(f"{Colors.GREEN}[+] 识别到 {len(self.fingerprint_results)} 个指纹:{Colors.END}")
            
            # 直接显示所有指纹，不分类
            for i, fp in enumerate(self.fingerprint_results[:20]):  # 最多显示20个
                exploit_info = ""
                if hasattr(fp, 'exploit_hint') and fp.exploit_hint:
                    exploit_info = f" {Colors.RED}[{fp.exploit_hint}]{Colors.END}"
                logger.info(f"  {i+1}. {fp.icon} {fp.name} - 置信度: {fp.confidence}%{exploit_info}")
                logger.info(f"     类别: {fp.category} | 证据: {fp.evidence[:80]}...")
            
            if len(self.fingerprint_results) > 20:
                logger.info(f"  ... 还有 {len(self.fingerprint_results) - 20} 个指纹")
            
            # 显示利用提示汇总
            exploits = [fp for fp in self.fingerprint_results if hasattr(fp, 'exploit_hint') and fp.exploit_hint]
            if exploits:
                logger.info(f"\n{Colors.RED}[!] 发现 {len(exploits)} 个可能存在漏洞的系统:{Colors.END}")
                for fp in exploits[:10]:
                    logger.info(f"    ⚠️ {fp.name}: {fp.exploit_hint}")
        else:
            logger.info(f"{Colors.YELLOW}[-] 未识别到明显指纹{Colors.END}")
        
        return self.fingerprint_results
    

    def parse_api_documentation(self, base_url: str) -> List[ParsedAPIDoc]:
        """
        解析API文档
        
        Args:
            base_url: 基础URL
            
        Returns:
            解析后的API文档列表
        """
        logger.info(f"{Colors.CYAN}[*] 开始搜索API文档...{Colors.END}")
        logger.debug(f"[parse_api_documentation] api_parse={self.api_parse}")
        
        try:
            self.parsed_api_docs = self.api_doc_parser.discover_and_parse(base_url)
            
            if self.parsed_api_docs:
                total_endpoints = sum(len(doc.endpoints) for doc in self.parsed_api_docs)
                logger.info(f"{Colors.GREEN}[+] 发现 {len(self.parsed_api_docs)} 个API文档，共 {total_endpoints} 个端点{Colors.END}")
                
                for doc in self.parsed_api_docs:
                    logger.info(f"    📄 {doc.title} (v{doc.version}) - {len(doc.endpoints)} 个端点")
                    
                    # 将API文档中的端点添加到扫描队列
                    for endpoint in doc.endpoints:
                        self.api_doc_endpoints.append(endpoint)
                        
                        # 转换为Endpoint对象添加到扫描列表 - 使用相对路径
                        # 构建完整URL用于显示，但存储相对路径
                        full_url = urljoin(doc.base_url or base_url, endpoint.path)
                        parsed = urlparse(full_url)
                        endpoint_path = parsed.path if parsed.path else endpoint.path
                        
                        # 如果路径不以/开头，添加/
                        if not endpoint_path.startswith('/'):
                            endpoint_path = '/' + endpoint_path
                        
                        self.endpoints.append(Endpoint(
                            url=endpoint_path,
                            method=endpoint.method,
                            source_js=f"API文档: {doc.title}",
                            params=[p.get('name', '') for p in endpoint.parameters],
                            api_type="api_doc"
                        ))
            else:
                logger.info(f"{Colors.YELLOW}[-] 未发现API文档{Colors.END}")
        except Exception as e:
            logger.debug(f"API文档解析错误: {e}")
        
        self._run_swagger_hound(base_url)
        
        return self.parsed_api_docs
    
    def _run_swagger_hound(self, base_url: str):
        """运行SwaggerHound进行API测试"""
        logger.debug(f"[_run_swagger_hound] api_parse={self.api_parse}")
        if not self.api_parse:
            logger.info(f"{Colors.YELLOW}[-] SwaggerHound 未启用 (api_parse=False){Colors.END}")
            return
        
        logger.info(f"{Colors.CYAN}[*] 启动 SwaggerHound API测试...{Colors.END}")
        
        try:
            proxies = None
            if self.proxy:
                proxies = {'http': self.proxy, 'https': self.proxy}
            
            hound = SwaggerHound(self.session, proxies)
            findings = hound.discover_and_scan(base_url)
            
            if findings:
                logger.info(f"{Colors.GREEN}[+] SwaggerHound 发现 {len(findings)} 个可访问接口{Colors.END}")
                
                for finding in findings:
                    url = finding.get('url', '')
                    method = finding.get('method', 'GET')
                    summary = finding.get('summary', '')
                    status_code = finding.get('status_code', 0)
                    response = finding.get('response', '')
                    params = finding.get('params', {})
                    
                    endpoint_key = (url, method)
                    if endpoint_key not in self.endpoint_urls:
                        self.endpoint_urls.add(endpoint_key)
                        self.endpoints.append(Endpoint(
                            url=url,
                            method=method,
                            source_js=f"SwaggerHound测试",
                            params=list(params.keys()) if params else [],
                            api_type="swagger_test"
                        ))
                    
                    finding_key = (url, 'SwaggerHound API测试', summary)
                    if finding_key not in self.result_keys:
                        self.result_keys.add(finding_key)
                        self.results.append(ScanResult(
                            url=url,
                            type="API接口测试",
                            severity="Info",
                            finding=f"{method} {summary}" if summary else f"{method} {url}",
                            detail=f"状态码: {status_code}\n响应: {response[:200]}..." if response else f"状态码: {status_code}",
                            source="SwaggerHound"
                        ))
            else:
                logger.info(f"{Colors.YELLOW}[-] SwaggerHound 未发现可访问的接口{Colors.END}")
                
        except Exception as e:
            logger.debug(f"SwaggerHound 测试错误: {e}")
    
    def _get_baseline(self, url: str, params: Dict, method: str = "GET") -> Dict:
        """获取正常请求的基准线响应特征"""
        cache_key = f"{method}:{url}:{sorted(params.keys())}"
        
        with self._lock:
            if cache_key in self.baseline_cache:
                return self.baseline_cache[cache_key]
        
        try:
            # 发送正常请求获取基准线
            normal_params = {k: "normal_test_value_123" for k in params.keys()}
            
            if method == "POST":
                resp = self.session.post(url, data=normal_params, timeout=self.timeout)
            else:
                resp = self.session.get(url, params=normal_params, timeout=self.timeout)
            
            baseline = {
                "status_code": resp.status_code,
                "content_length": len(resp.text),
                "content_hash": hashlib.md5(resp.text.encode()).hexdigest()[:16],
                "error_keywords": [err for err in self.SQLI_ERRORS if err in resp.text.lower()],
                "headers": dict(resp.headers)
            }
            
            with self._lock:
                self.baseline_cache[cache_key] = baseline
            
            return baseline
        except Exception as e:
            logger.debug(f"获取基准线失败: {e}")
            return {"status_code": 200, "content_length": 0, "content_hash": "", "error_keywords": []}
    
    def _is_significant_difference(self, resp, baseline: Dict, vuln_type: str) -> Tuple[bool, str]:
        """判断响应是否与基准线有显著差异"""
        current_length = len(resp.text)
        current_hash = hashlib.md5(resp.text.encode()).hexdigest()[:16]
        current_status = resp.status_code
        resp_text_lower = resp.text.lower()
        
        # 1. 状态码变化
        if current_status != baseline.get("status_code", 200):
            if current_status in [500, 502, 503]:
                return True, f"状态码变化: {baseline.get('status_code')} -> {current_status} (服务器错误)"
        
        # 2. 内容长度显著变化 (>50%)
        baseline_length = baseline.get("content_length", 0)
        if baseline_length > 0:
            length_diff_ratio = abs(current_length - baseline_length) / baseline_length
            if length_diff_ratio > 0.5:
                return True, f"内容长度显著变化: {baseline_length} -> {current_length} ({length_diff_ratio:.0%})"
        
        # 3. SQLi特定检测：出现新的SQL错误
        if vuln_type == "SQL Injection":
            current_errors = [err for err in self.SQLI_ERRORS if err in resp_text_lower]
            baseline_errors = set(baseline.get("error_keywords", []))
            new_errors = [e for e in current_errors if e not in baseline_errors]
            if new_errors:
                return True, f"出现新的SQL错误: {', '.join(new_errors[:2])}"
        
        # 4. XSS特定检测：payload被反射且未转义
        if vuln_type == "XSS":
            # 这里由调用方检查
            pass
        
        # 5. 内容哈希完全不同（且长度差异明显）
        if current_hash != baseline.get("content_hash", ""):
            if baseline_length > 0 and abs(current_length - baseline_length) > 100:
                return True, "页面内容结构发生变化"
        
        return False, ""
    
    def test_sqli(self, url: str, params: Dict, method: str = "GET") -> List[VulnFinding]:
        """SQL注入测试 - 带基准线差分检测和WAF绕过"""
        findings = []
        
        if not params:
            return findings
        
        # 获取基准线
        baseline = self._get_baseline(url, params, method)
        
        # 基础payloads
        base_payloads = ["'", "' OR '1'='1", "' OR 1=1--"]
        
        # 如果WAF绕过模式启用，添加绕过payloads
        if self.waf_bypass_mode:
            bypass_payloads = self.get_bypass_payloads("sqli")
            test_payloads = base_payloads + bypass_payloads
            logger.debug(f"使用 {len(test_payloads)} 个SQL注入payloads (含WAF绕过)")
        else:
            test_payloads = base_payloads
        
        for param_name in params.keys():
            for payload in test_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    # 使用绕过请求方法
                    resp = self.make_bypass_request(url, method, test_params, test_params)
                    
                    if resp is None:
                        continue
                    
                    # 差分检测
                    is_vuln, detail = self._is_significant_difference(resp, baseline, "SQL Injection")
                    
                    if is_vuln:
                        # 额外验证：检查是否是真实的SQL注入（排除测试代码/示例）
                        if self._verify_sqli_real(resp, payload):
                            findings.append(VulnFinding(
                                url=url,
                                vuln_type="SQL Injection",
                                severity="Critical",
                                param=param_name,
                                payload=payload,
                                detail=f"差分检测确认: {detail}"
                            ))
                            break
                        else:
                            logger.debug(f"SQL注入可能是误报，跳过: {payload[:30]}...")
                        
                except Exception as e:
                    logger.debug(f"SQLi test error: {e}")
        
        return findings
    
    def test_xss(self, url: str, params: Dict, method: str = "GET") -> List[VulnFinding]:
        """XSS测试 - 带基准线差分检测和WAF绕过"""
        findings = []
        
        if not params:
            return findings
        
        # 获取基准线
        baseline = self._get_baseline(url, params, method)
        baseline_hash = baseline.get("content_hash", "")
        
        # 基础payloads
        base_payloads = self.XSS_PAYLOADS[:3]
        
        # 如果WAF绕过模式启用，添加绕过payloads
        if self.waf_bypass_mode:
            bypass_payloads = self.get_bypass_payloads("xss")
            test_payloads = base_payloads + bypass_payloads
            logger.debug(f"使用 {len(test_payloads)} 个XSS payloads (含WAF绕过)")
        else:
            test_payloads = base_payloads
        
        for payload in test_payloads:
            try:
                test_params = {k: payload for k in params.keys()}
                
                # 使用绕过请求方法
                resp = self.make_bypass_request(url, method, test_params, test_params)
                
                if resp is None:
                    continue
                
                resp_text = resp.text
                current_hash = hashlib.md5(resp_text.encode()).hexdigest()[:16]
                
                # 检查payload是否被反射且未转义
                if payload in resp_text:
                    # 检查是否被转义（简单的检查）
                    escaped_payload = payload.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
                    if escaped_payload not in resp_text:
                        # payload未被转义，可能是XSS
                        # 进一步检查：payload是否在script标签或事件处理器中
                        context = self._check_xss_context(resp_text, payload)
                        if context["vulnerable"]:
                            # 额外验证：检查响应中是否包含大量测试payload（可能是测试代码本身）
                            payload_count = resp_text.count(payload)
                            if payload_count > 5:
                                logger.debug(f"跳过可能的测试代码: {payload[:30]}... 出现{payload_count}次")
                                continue
                            
                            # 验证：检查是否是真实的XSS（payload在正确的上下文中可执行）
                            if self._verify_xss_executable(resp_text, payload):
                                findings.append(VulnFinding(
                                    url=url,
                                    vuln_type="XSS",
                                    severity="High",
                                    param=list(test_params.keys())[0],
                                    payload=payload,
                                    detail=f"反射型XSS - 上下文: {context['type']}"
                                ))
                                break
                    
            except Exception as e:
                logger.debug(f"XSS test error: {e}")
        
        return findings
    
    def _check_xss_context(self, content: str, payload: str) -> Dict:
        """检查XSS payload在响应中的上下文"""
        result = {"vulnerable": False, "type": "unknown"}
        
        # 查找payload位置
        idx = content.find(payload)
        if idx == -1:
            return result
        
        # 获取上下文（前后100字符）
        start = max(0, idx - 100)
        end = min(len(content), idx + len(payload) + 100)
        context = content[start:end]
        
        # 检查是否在script标签中
        if re.search(r'<script[^>]*>.*?' + re.escape(payload), context, re.DOTALL | re.IGNORECASE):
            result = {"vulnerable": True, "type": "script_context"}
        # 检查是否在HTML属性中
        elif re.search(r'\s(on\w+|href|src|action)\s*=\s*["\'][^"\']*' + re.escape(payload), context, re.IGNORECASE):
            result = {"vulnerable": True, "type": "attribute_context"}
        # 检查是否在HTML标签内
        elif re.search(r'<[^>]+>[^<]*' + re.escape(payload), context):
            result = {"vulnerable": True, "type": "html_context"}
        # 检查是否在style中
        elif re.search(r'<style[^>]*>.*?' + re.escape(payload), context, re.DOTALL | re.IGNORECASE):
            result = {"vulnerable": True, "type": "style_context"}
        
        return result
    
    def _verify_xss_executable(self, content: str, payload: str) -> bool:
        """
        验证XSS payload是否在可执行的上下文中
        过滤掉被注释、字符串字面量或测试代码中的payload
        """
        idx = content.find(payload)
        if idx == -1:
            return False
        
        # 获取更广泛的上下文（前后200字符）
        start = max(0, idx - 200)
        end = min(len(content), idx + len(payload) + 200)
        context = content[start:end]
        
        # 检查是否在HTML注释中
        comment_pattern = r'<!--.*?-->'
        for match in re.finditer(comment_pattern, context, re.DOTALL):
            if match.start() <= (idx - start) <= match.end():
                logger.debug(f"XSS payload在HTML注释中，跳过")
                return False
        
        # 检查是否在JS字符串字面量中
        js_string_pattern = r'["\']([^"\']*?' + re.escape(payload) + r'[^"\']*?)["\']'
        if re.search(js_string_pattern, context):
            # 进一步检查是否在可执行的上下文中
            # 例如：var x = "<script>" 是不可执行的
            # 但：eval("<script>") 是可执行的
            if not re.search(r'eval\s*\(|Function\s*\(|setTimeout\s*\(|setInterval\s*\(', context):
                logger.debug(f"XSS payload在JS字符串字面量中且无可执行上下文，跳过")
                return False
        
        # 检查是否在CSS/Style注释中
        if re.search(r'/\*.*?\*/', context, re.DOTALL):
            css_comment = re.search(r'/\*.*?\*/', context, re.DOTALL)
            if css_comment and css_comment.start() <= (idx - start) <= css_comment.end():
                logger.debug(f"XSS payload在CSS注释中，跳过")
                return False
        
        # 检查是否是测试/示例代码（包含test、example、sample等关键词）
        test_keywords = ['test', 'example', 'sample', 'demo', 'mock', 'fixture', 'spec']
        surrounding_text = content[max(0, idx-500):min(len(content), idx+len(payload)+500)].lower()
        if any(kw in surrounding_text for kw in test_keywords):
            # 进一步检查：如果payload出现在代码注释或文档中，可能是示例
            if re.search(r'(//|#|<!--).*?' + re.escape(payload[:20]), surrounding_text, re.IGNORECASE):
                logger.debug(f"XSS payload在测试/示例代码中，跳过")
                return False
        
        return True
    
    def _verify_sqli_real(self, resp, payload: str) -> bool:
        """
        验证SQL注入是否真实存在（排除误报）
        过滤测试代码、示例、文档中的SQL错误
        """
        resp_text = resp.text
        resp_lower = resp_text.lower()
        
        # 1. 检查响应中是否包含大量payload（可能是测试代码）
        payload_count = resp_text.count(payload)
        if payload_count > 3:
            logger.debug(f"SQL payload出现{payload_count}次，可能是测试代码")
            return False
        
        # 2. 检查是否在代码注释中（HTML注释、JS注释等）
        # HTML注释
        html_comment_pattern = r'<!--.*?-->'
        for match in re.finditer(html_comment_pattern, resp_text, re.DOTALL):
            if payload in match.group(0):
                logger.debug(f"SQL payload在HTML注释中，跳过")
                return False
        
        # JS/CSS注释
        js_comment_pattern = r'/\*.*?\*/'
        for match in re.finditer(js_comment_pattern, resp_text, re.DOTALL):
            if payload in match.group(0):
                logger.debug(f"SQL payload在JS/CSS注释中，跳过")
                return False
        
        # 单行注释
        single_line_comments = re.findall(r'//.*$', resp_text, re.MULTILINE)
        for comment in single_line_comments:
            if payload in comment:
                logger.debug(f"SQL payload在单行注释中，跳过")
                return False
        
        # 3. 检查是否是测试/示例代码
        test_keywords = ['test', 'example', 'sample', 'demo', 'mock', 'fixture', 'spec', 'tutorial']
        surrounding_text = resp_lower[max(0, resp_lower.find(payload.lower())-1000):min(len(resp_lower), resp_lower.find(payload.lower())+len(payload)+1000)]
        if any(kw in surrounding_text for kw in test_keywords):
            logger.debug(f"SQL payload在测试/示例代码附近，谨慎处理")
            # 进一步检查SQL错误是否出现在代码块中
            code_block_pattern = r'<code>.*?</code>|<pre>.*?</pre>|```.*?```'
            for match in re.finditer(code_block_pattern, resp_lower, re.DOTALL):
                if any(err in match.group(0) for err in self.SQLI_ERRORS):
                    logger.debug(f"SQL错误在代码块中，可能是示例")
                    return False
        
        # 4. 检查SQL错误是否是文档的一部分（如API文档中的错误示例）
        doc_keywords = ['documentation', 'api reference', 'error code', 'status code', 'response example']
        if any(kw in resp_lower for kw in doc_keywords):
            # 检查错误是否出现在示例/代码块中
            if re.search(r'<(code|pre|samp)>.*?(sql|error|syntax)', resp_lower, re.DOTALL):
                logger.debug(f"SQL错误在API文档示例中，跳过")
                return False
        
        # 5. 检查是否是Swagger/OpenAPI文档
        if 'swagger' in resp_lower or 'openapi' in resp_lower:
            # Swagger文档经常包含SQL示例
            if resp_lower.count('example') > 5 or resp_lower.count('schema') > 5:
                logger.debug(f"可能是Swagger/OpenAPI文档，跳过SQL注入检测")
                return False
        
        return True
    
    def test_lfi(self, url: str, params: Dict, method: str = "GET") -> List[VulnFinding]:
        """LFI测试 - 带WAF绕过"""
        findings = []
        
        if not params:
            return findings
        
        param_name = list(params.keys())[0]
        
        # 基础payloads
        base_payloads = self.LFI_PATHS[:3]
        
        # 如果WAF绕过模式启用，添加绕过payloads
        if self.waf_bypass_mode:
            bypass_payloads = self.get_bypass_payloads("lfi")
            test_payloads = base_payloads + bypass_payloads
            logger.debug(f"使用 {len(test_payloads)} 个LFI payloads (含WAF绕过)")
        else:
            test_payloads = base_payloads
        
        for payload in test_payloads:
            try:
                test_params = params.copy()
                test_params[param_name] = payload
                
                # 使用绕过请求方法
                resp = self.make_bypass_request(url, method, test_params, test_params)
                
                if resp is None:
                    continue
                
                if "root:" in resp.text or "[boot loader]" in resp.text:
                    findings.append(VulnFinding(
                        url=url,
                        vuln_type="LFI",
                        severity="High",
                        param=param_name,
                        payload=payload,
                        detail="本地文件读取"
                    ))
                    break
                    
            except Exception as e:
                logger.debug(f"LFI test error: {e}")
        
        return findings
    
    def test_rce(self, url: str, params: Dict, method: str = "GET") -> List[VulnFinding]:
        """RCE测试 - 带WAF绕过"""
        findings = []
        
        if not params:
            return findings
        
        param_name = list(params.keys())[0]
        
        # 基础payloads
        base_payloads = self.RCE_PAYLOADS[:3]
        
        # 如果WAF绕过模式启用，添加绕过payloads
        if self.waf_bypass_mode:
            bypass_payloads = self.get_bypass_payloads("rce")
            test_payloads = base_payloads + bypass_payloads
            logger.debug(f"使用 {len(test_payloads)} 个RCE payloads (含WAF绕过)")
        else:
            test_payloads = base_payloads
        
        for payload in test_payloads:
            try:
                test_params = params.copy()
                test_params[param_name] = payload
                
                # 使用绕过请求方法
                resp = self.make_bypass_request(url, method, test_params, test_params)
                
                if resp is None:
                    continue
                
                if any(indicator in resp.text for indicator in ["root:", "daemon:", "bin/bash"]):
                    findings.append(VulnFinding(
                        url=url,
                        vuln_type="RCE",
                        severity="Critical",
                        param=param_name,
                        payload=payload,
                        detail="远程代码执行"
                    ))
                    break
                    
            except Exception as e:
                logger.debug(f"RCE test error: {e}")
        
        return findings
    
    def detect_jsonp(self, content: str, base_url: str) -> List[ScanResult]:
        findings = []
        
        pattern = r'(?i)(?:callback|jsonp|cb)\s*=\s*([a-zA-Z_][a-zA-Z0-9_]*)'
        matches = re.findall(pattern, content)
        
        for callback in set(matches):
            finding = ScanResult(
                url=base_url,
                type="jsonp",
                severity="Medium",
                finding=f"JSONP端点: ?{callback}=...",
                detail=f"callback函数: {callback}",
                source=base_url
            )
            findings.append(finding)
        
        return findings
    
    def detect_cors(self, url: str) -> Optional[ScanResult]:
        try:
            test_origin = "https://evil.com"
            headers = dict(self.headers)
            headers['Origin'] = test_origin
            
            resp = self.session.options(url, headers=headers, timeout=self.timeout)
            
            ac_allow = resp.headers.get('Access-Control-Allow-Origin', '')
            ac_cred = resp.headers.get('Access-Control-Allow-Credentials', '')
            
            if ac_allow == '*' or (ac_allow == test_origin and ac_cred == 'true'):
                return ScanResult(
                    url=url,
                    type="cors",
                    severity="Medium",
                    finding=f"CORS配置不当: {ac_allow}",
                    detail=f"Allow-Origin: {ac_allow}, Allow-Credentials: {ac_cred}",
                    source=url
                )
        except:
            pass
        return None
    
    def detect_ssrf_params(self) -> List[ScanResult]:
        findings = []
        seen_ssrf = set()
        
        for ep in self.endpoints:
            parsed = urlparse(ep.url)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                if any(x in param.lower() for x in ['url', 'link', 'src', 'path', 'uri', 'domain', 'redirect', 'rurl', 'next', 'data', 'reference', 'site', 'html', 'val', 'validate', 'domain', 'callback', 'return', 'page', 'feed', 'host', 'port', 'to', 'out', 'view', 'dir', 'show', 'navigation', 'open', 'file', 'document', 'folder', 'pg', 'style', 'doc', 'img', 'source', 'target', 'q', 'query', 'pageid', 'action', 'collection']):
                    key = (ep.url, param)
                    if key in seen_ssrf:
                        continue
                    seen_ssrf.add(key)
                    
                    findings.append(ScanResult(
                        url=ep.url,
                        type="ssrf",
                        severity="High",
                        finding=f"可能存在SSRF的参数: {param}",
                        detail=f"URL: {ep.url}",
                        source=ep.source_js
                    ))
        
        return findings
    
    def extract_subdomains(self, content: str) -> List[str]:
        subdomains = []
        
        pattern = r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.' + re.escape(self.base_domain) + r')'
        matches = re.findall(pattern, content, re.I)
        
        for match in matches:
            if match != self.base_domain and match not in self.subdomains:
                self.subdomains.add(match)
                subdomains.append(match)
        
        return subdomains
    
    def _is_template_url(self, url: str) -> bool:
        """检查URL是否包含模板语法，如 {{...}} 或 ${...}"""
        if not url:
            return False
        # 检查常见的模板语法
        template_patterns = [
            r'\{\{[^}]*\}\}',  # {{...}}
            r'\$\{[^}]*\}',      # ${...}
            r'@\{[^}]*\}',       # @{...}
            r'\[\[.*?\]\]',      # [[...]]
            r'\{%.*?%\}',        # {%...%}
        ]
        for pattern in template_patterns:
            if re.search(pattern, url):
                return True
        return False
    
    def extract_page_links(self, html_content: str, base_url: str) -> List[str]:
        """提取页面中的链接"""
        links = []
        base_parsed = urlparse(base_url)
        base_domain = base_parsed.netloc
        
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                
                if not href or href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:'):
                    continue
                
                # 跳过包含模板语法的URL
                if self._is_template_url(href):
                    logger.debug(f"跳过模板URL: {href}")
                    continue
                
                if not href.startswith(('http://', 'https://')):
                    href = urljoin(base_url, href)
                
                parsed = urlparse(href)
                
                if href.startswith('http') and base_domain in href:
                    clean_url = parsed.scheme + '://' + parsed.netloc + parsed.path
                    links.append(clean_url)
            
            for iframe_tag in soup.find_all('iframe', src=True):
                src = iframe_tag['src']
                if src and not src.startswith('javascript:'):
                    if not src.startswith(('http://', 'https://')):
                        src = urljoin(base_url, src)
                    parsed = urlparse(src)
                    if base_domain in parsed.netloc:
                        clean_url = parsed.scheme + '://' + parsed.netloc + parsed.path
                        links.append(clean_url)
            
            for img_tag in soup.find_all('img', src=True):
                src = img_tag['src']
                if src and not src.startswith('data:'):
                    if not src.startswith(('http://', 'https://')):
                        src = urljoin(base_url, src)
                    parsed = urlparse(src)
                    if base_domain in parsed.netloc and parsed.path.endswith(('.js', '.css')):
                        links.append(src)
            
            for link_tag in soup.find_all('link', href=True):
                href = link_tag['href']
                if href and href.endswith('.js'):
                    if not href.startswith(('http://', 'https://')):
                        href = urljoin(base_url, href)
                    parsed = urlparse(href)
                    if base_domain in parsed.netloc:
                        links.append(href)
            
            for script_tag in soup.find_all('script', src=True):
                src = script_tag['src']
                if src:
                    if not src.startswith(('http://', 'https://')):
                        src = urljoin(base_url, src)
                    parsed = urlparse(src)
                    if base_domain in parsed.netloc:
                        links.append(src)
                        
        except Exception as e:
            pass
        
        link_patterns = [
            r'href\s*=\s*["\']([^"\']+)["\']',
            r'src\s*=\s*["\']([^"\']+)["\']',
            r'window\.location\.href\s*=\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']',
            r'url\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in link_patterns:
            for match in re.finditer(pattern, html_content, re.I):
                href = match.group(1)
                
                if not href or href.startswith('#') or href.startswith('javascript:') or href.startswith('mailto:') or href.startswith('data:'):
                    continue
                
                # 跳过包含模板语法的URL
                if self._is_template_url(href):
                    logger.debug(f"跳过模板URL: {href}")
                    continue
                
                if not href.startswith(('http://', 'https://')):
                    href = urljoin(base_url, href)
                
                parsed = urlparse(href)
                
                if href.startswith('http') and base_domain in parsed.netloc:
                    links.append(href)
        
        # 最后过滤一次，确保没有模板URL
        filtered_links = []
        for link in links:
            if not self._is_template_url(link):
                filtered_links.append(link)
            else:
                logger.debug(f"过滤模板URL: {link}")
        
        return list(set(filtered_links))
    
    def extract_forms(self, html_content: str, page_url: str) -> List[FormInput]:
        """提取页面中的表单"""
        forms = []
        
        form_pattern = r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*method=["\']?([^"\'>\s]+)["\']?[^>]*>(.*?)</form>'
        for match in re.finditer(form_pattern, html_content, re.I | re.DOTALL):
            action = match.group(1).strip()
            method = match.group(2).strip().upper() if match.group(2) else "POST"
            form_html = match.group(3)
            
            if not action or action == "#":
                action = page_url
            elif not action.startswith(('http://', 'https://')):
                action = urljoin(page_url, action)
            
            input_pattern = r'<input[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*type=["\']?([^"\'>\s]+)["\']?[^>]*>'
            inputs = []
            for input_match in re.finditer(input_pattern, form_html, re.I):
                input_name = input_match.group(1).strip()
                input_type = input_match.group(2).strip().lower() if input_match.group(2) else "text"
                
                if input_name and input_type not in ['submit', 'button', 'reset']:
                    inputs.append({
                        'name': input_name,
                        'type': input_type
                    })
            
            if inputs:
                forms.append(FormInput(
                    url=page_url,
                    method=method,
                    action=action,
                    inputs=inputs,
                    form_type="form"
                ))
                logger.info(f"{Colors.CYAN}[+] 发现表单: {action} ({method}) - {len(inputs)} 个输入字段{Colors.END}")
        
        return forms
    
    def extract_input_points(self, html_content: str, page_url: str) -> List[Dict]:
        """提取页面中的其他输入点（如URL参数、JSON API等）"""
        input_points = []
        
        url_params = parse_qs(urlparse(page_url).query)
        if url_params:
            input_points.append({
                'type': 'url_param',
                'url': page_url,
                'method': 'GET',
                'params': list(url_params.keys())
            })
        
        # 从JS中提取API调用参数
        api_params = self._extract_api_params_from_js(html_content)
        for api_info in api_params:
            input_points.append({
                'type': 'api_param',
                'url': api_info.get('url', page_url),
                'method': api_info.get('method', 'GET'),
                'params': api_info.get('params', [])
            })
        
        return input_points
    
    def _extract_api_params_from_js(self, js_content: str) -> List[Dict]:
        """
        从JS代码中提取API调用参数
        例如: $.ajax({url: '/api/user', data: {id: 1, name: 'test'}})
        """
        api_calls = []
        
        # 匹配fetch API参数
        fetch_pattern = r'fetch\s*\(\s*["\']([^"\']+)["\']\s*,\s*\{[^}]*method\s*:\s*["\']([^"\']+)["\'][^}]*body\s*:\s*([^}]+)'
        for match in re.finditer(fetch_pattern, js_content, re.I):
            url = match.group(1)
            method = match.group(2).upper()
            body = match.group(3)
            # 提取body中的参数名
            params = self._extract_params_from_body(body)
            api_calls.append({'url': url, 'method': method, 'params': params})
        
        # 匹配$.ajax参数
        ajax_pattern = r'\$\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\'][^}]*data\s*:\s*\{([^}]+)\}'
        for match in re.finditer(ajax_pattern, js_content, re.I):
            url = match.group(1)
            data = match.group(2)
            params = self._extract_param_names(data)
            api_calls.append({'url': url, 'method': 'POST', 'params': params})
        
        # 匹配axios参数
        axios_pattern = r'axios\.(get|post|put|delete)\s*\(\s*["\']([^"\']+)["\']\s*,?\s*(?:\{[^}]*params\s*:\s*\{([^}]+)\})?'
        for match in re.finditer(axios_pattern, js_content, re.I):
            method = match.group(1).upper()
            url = match.group(2)
            params_str = match.group(3) if match.group(3) else ""
            params = self._extract_param_names(params_str)
            api_calls.append({'url': url, 'method': method, 'params': params})
        
        # 匹配XMLHttpRequest
        xhr_pattern = r'new\s+XMLHttpRequest\(\)[\s\S]*?open\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']'
        for match in re.finditer(xhr_pattern, js_content, re.I):
            method = match.group(1).upper()
            url = match.group(2)
            api_calls.append({'url': url, 'method': method, 'params': []})
        
        return api_calls
    
    def _extract_params_from_body(self, body_str: str) -> List[str]:
        """从请求体字符串中提取参数名"""
        params = []
        # 匹配JSON.stringify({key: value})
        json_pattern = r'(\w+)\s*:\s*[^,}]+'
        for match in re.finditer(json_pattern, body_str):
            params.append(match.group(1))
        return params
    
    def _extract_param_names(self, data_str: str) -> List[str]:
        """从data字符串中提取参数名"""
        params = []
        # 匹配 key: value 或 "key": value
        param_pattern = r'["\']?(\w+)["\']?\s*:\s*'
        for match in re.finditer(param_pattern, data_str):
            params.append(match.group(1))
        return params
    
    def fuzz_api_params(self, endpoint: Endpoint, param_list: List[str]) -> List[VulnFinding]:
        """
        对API参数进行Fuzzing测试
        """
        findings = []
        
        if not param_list:
            return findings
        
        logger.info(f"{Colors.CYAN}[*] 对 {endpoint.url} 进行参数Fuzzing ({len(param_list)} 个参数){Colors.END}")
        
        # 构建基础URL
        base_url = endpoint.url
        method = endpoint.method
        
        # 获取基准线
        normal_params = {p: "normal_test_123" for p in param_list}
        baseline = self._get_baseline(base_url, normal_params, method)
        
        # SQL注入测试
        sqli_payloads = ["'", "' OR '1'='1", "' OR 1=1--", "1 AND 1=1", "1 AND 1=2"]
        for param in param_list:
            for payload in sqli_payloads:
                try:
                    test_params = {p: "normal_test_123" for p in param_list}
                    test_params[param] = payload
                    
                    if method == "POST":
                        resp = self.session.post(base_url, data=test_params, timeout=self.timeout)
                    else:
                        resp = self.session.get(base_url, params=test_params, timeout=self.timeout)
                    
                    is_vuln, detail = self._is_significant_difference(resp, baseline, "SQL Injection")
                    if is_vuln:
                        findings.append(VulnFinding(
                            url=base_url,
                            vuln_type="SQL Injection",
                            severity="Critical",
                            param=param,
                            payload=payload,
                            detail=f"参数Fuzzing发现: {detail}"
                        ))
                        break
                except Exception as e:
                    logger.debug(f"参数Fuzzing错误: {e}")
        
        # XSS测试
        xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        for param in param_list:
            for payload in xss_payloads:
                try:
                    test_params = {p: "normal_test_123" for p in param_list}
                    test_params[param] = payload
                    
                    if method == "POST":
                        resp = self.session.post(base_url, data=test_params, timeout=self.timeout)
                    else:
                        resp = self.session.get(base_url, params=test_params, timeout=self.timeout)
                    
                    if payload in resp.text:
                        context = self._check_xss_context(resp.text, payload)
                        if context["vulnerable"]:
                            findings.append(VulnFinding(
                                url=base_url,
                                vuln_type="XSS",
                                severity="High",
                                param=param,
                                payload=payload,
                                detail=f"参数Fuzzing发现XSS: {context['type']}"
                            ))
                            break
                except Exception as e:
                    logger.debug(f"XSS Fuzzing错误: {e}")
        
        return findings
    
    SENSITIVE_PATHS = [
        "/admin", "/login", "/dashboard", "/config", "/settings",
        "/api/admin", "/api/v1/admin", "/manage", "/phpmyadmin",
        "/.git/config", "/.svn/entries", "/.env", "/wp-admin",
        "/backup", "/uploads", "/files", "/images", "/static",
        "/api/users", "/api/auth", "/api/login", "/api/token",
        "/swagger", "/swagger-ui", "/api-docs", "/v2/api-docs",
        "/actuator", "/actuator/health", "/actuator/env",
        "/server-status", "/server-info", "/phpinfo",
        "/shell", "/cmd", "/exec", "/system",
    ]
    
    def add_result(self, result: ScanResult) -> bool:
        """线程安全地添加扫描结果"""
        key = (result.url, result.type, result.finding)
        with self._lock:
            if key in self.result_keys:
                return False
            self.result_keys.add(key)
            self.results.append(result)
        return True
    
    def add_vuln_finding(self, finding: VulnFinding) -> bool:
        """线程安全地添加漏洞发现"""
        key = (finding.url, finding.vuln_type, finding.param)
        with self._lock:
            if key in self.vuln_keys:
                return False
            self.vuln_keys.add(key)
            self.vuln_findings.append(finding)
        return True
    
    def is_url_visited(self, url: str) -> bool:
        """线程安全地检查URL是否已访问"""
        with self._lock:
            return url in self.visited_urls
    
    def mark_url_visited(self, url: str):
        """线程安全地标记URL已访问"""
        with self._lock:
            self.visited_urls.add(url)
    
    def is_page_crawled(self, url: str) -> bool:
        """线程安全地检查页面是否已爬取"""
        with self._lock:
            return url in self.crawled_pages
    
    def mark_page_crawled(self, url: str):
        """线程安全地标记页面已爬取"""
        with self._lock:
            self.crawled_pages.add(url)
    
    def is_js_visited(self, url: str) -> bool:
        """线程安全地检查JS是否已访问"""
        with self._lock:
            return url in self.visited_js
    
    def mark_js_visited(self, url: str):
        """线程安全地标记JS已访问"""
        with self._lock:
            self.visited_js.add(url)
    
    def fuzz_sensitive_paths(self, target_url: str) -> List[ScanResult]:
        findings = []
        
        parsed = urlparse(target_url)
        base_path = f"{parsed.scheme}://{parsed.netloc}"
        
        logger.info(f"{Colors.CYAN}[*] 开始路径fuzzing...{Colors.END}")
        
        for path in self.SENSITIVE_PATHS:
            test_url = base_path + path
            
            try:
                resp = self.session.get(test_url, headers=self.headers, timeout=5, allow_redirects=False)
                
                if resp.status_code == 200:
                    findings.append(ScanResult(
                        url=test_url,
                        type="sensitive_path",
                        severity="High",
                        finding=f"敏感路径发现: {test_url}",
                        detail=f"路径: {path} | 状态码: {resp.status_code}",
                        source=target_url
                    ))
                    logger.info(f"{Colors.GREEN}[+] 发现敏感路径: {test_url}{Colors.END}")
                    
            except Exception as e:
                logger.debug(f"Path fuzz error: {e}")
        
        return findings
    
    def test_endpoints_vulns(self):
        if self.vuln_test:
            logger.info(f"{Colors.CYAN}[*] 开始增强漏洞测试...{Colors.END}")
            
            from vuln_test import VULN_TYPE_MAP
            
            tester = EnhancedVulnTester(self.session, self.timeout)
            
            all_findings = []
            
            logger.info(f"{Colors.CYAN}[*] 测试表单漏洞（实际发送Payload）...{Colors.END}")
            
            if not self.forms:
                logger.info(f"{Colors.YELLOW}[-] 未发现表单，跳过{Colors.END}")
            
            for form in self.forms:
                if not form.inputs:
                    continue
                    
                logger.info(f"{Colors.YELLOW}[+] 测试表单: {form.action} ({form.method}) - {len(form.inputs)}个输入{Colors.END}")
                
                params = {}
                for inp in form.inputs:
                    if inp['type'] in ['text', 'search', 'password', 'email', 'number', 'textarea']:
                        params[inp['name']] = "test"
                    elif inp['type'] == 'hidden':
                        params[inp['name']] = inp.get('value', 'test')
                
                if not params:
                    continue
                
                form_findings = []
                method = form.method.upper()
                
                logger.info(f"{Colors.CYAN}[  ] SQL注入测试...{Colors.END}")
                form_findings.extend(tester.test_sqli(form.action, params, method))
                
                logger.info(f"{Colors.CYAN}[  ] XSS测试...{Colors.END}")
                form_findings.extend(tester.test_xss(form.action, params, method))
                
                logger.info(f"{Colors.CYAN}[  ] LFI测试...{Colors.END}")
                form_findings.extend(tester.test_lfi(form.action, params, method))
                
                logger.info(f"{Colors.CYAN}[  ] RCE测试...{Colors.END}")
                form_findings.extend(tester.test_rce(form.action, params, method))
                
                logger.info(f"{Colors.CYAN}[  ] XXE测试...{Colors.END}")
                form_findings.extend(tester.test_xxe(form.action, params, method))
                
                file_input = any(inp.get('type') == 'file' for inp in form.inputs)
                if file_input:
                    logger.info(f"{Colors.CYAN}[*] 检测到文件上传表单: {form.action}{Colors.END}")
                    upload_findings = tester.test_file_upload(form.action, form.method, params)
                    form_findings.extend(upload_findings)
                
                if form_findings:
                    logger.info(f"{Colors.ORANGE}[*] 表单 {form.action} 发现 {len(form_findings)} 个问题{Colors.END}")
                
                all_findings.extend(form_findings)
            
            logger.info(f"{Colors.CYAN}[*] 测试API端点漏洞（实际发送Payload）...{Colors.END}")
            
            static_extensions = ('.js', '.css', '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.map')
            
            api_endpoints_for_test = []
            sensitive_endpoints = []
            for endpoint in self.endpoints:
                url_lower = endpoint.url.lower()
                if url_lower.endswith(static_extensions) or '.min.' in url_lower:
                    continue
                
                sensitive_keywords = ["/admin", "/user", "/order", "/pay", "/account", "/api/admin", "/api/user", "/dashboard", "/manage", "/config", "/delete", "/edit", "/update"]
                if any(kw in url_lower for kw in sensitive_keywords):
                    sensitive_endpoints.append(endpoint.url)
                
                if not endpoint.params:
                    if '?' in url_lower:
                        parsed = urlparse(endpoint.url)
                        query_params = parse_qs(parsed.query)
                        if query_params:
                            endpoint.params = list(query_params.keys())
                            api_endpoints_for_test.append(endpoint)
                else:
                    api_endpoints_for_test.append(endpoint)
            
            api_count = len(api_endpoints_for_test)
            logger.info(f"{Colors.YELLOW}[*] 待测试API数量: {api_count}{Colors.END}")
            
            tested_count = 0
            for endpoint in api_endpoints_for_test:
                if not endpoint.params:
                    continue
                
                tested_count += 1
                logger.info(f"{Colors.YELLOW}[{tested_count}/{api_count}] 测试: {endpoint.url}{Colors.END}")
                
                endpoint_findings = []
                params = {p: "test" for p in endpoint.params}
                
                # 导入增强版测试器（在条件分支外导入，确保两个分支都能使用）
                from vuln_test_enhanced import VulnTesterEnhanced
                enhanced_tester = VulnTesterEnhanced(self.session, self.timeout)
                
                if endpoint.method.upper() == "GET":
                    endpoint_findings.extend(tester.test_sqli(endpoint.url, params, "GET"))
                    endpoint_findings.extend(tester.test_xss(endpoint.url, params, "GET"))
                    endpoint_findings.extend(tester.test_lfi(endpoint.url, params, "GET"))
                    # 使用增强版RCE测试
                    endpoint_findings.extend(enhanced_tester.test_rce_enhanced(endpoint.url, params, "GET"))
                    # 使用增强版SSRF测试（支持DNSLog）
                    endpoint_findings.extend(enhanced_tester.test_ssrf_with_dnslog(endpoint.url, params, "GET"))
                    endpoint_findings.extend(tester.test_xxe(endpoint.url, params, "GET"))
                    endpoint_findings.extend(tester.test_command_injection(endpoint.url, params, "GET"))
                    endpoint_findings.extend(tester.test_path_traversal(endpoint.url, params, "GET"))
                    endpoint_findings.extend(tester.test_ssti(endpoint.url, params, "GET"))
                    endpoint_findings.extend(tester.test_ldap_injection(endpoint.url, params, "GET"))
                    endpoint_findings.extend(tester.test_no_sql_injection(endpoint.url, params, "GET"))
                else:
                    endpoint_findings.extend(tester.test_sqli(endpoint.url, params, endpoint.method))
                    endpoint_findings.extend(tester.test_xss(endpoint.url, params, endpoint.method))
                    endpoint_findings.extend(tester.test_lfi(endpoint.url, params, endpoint.method))
                    # 使用增强版RCE测试
                    endpoint_findings.extend(enhanced_tester.test_rce_enhanced(endpoint.url, params, endpoint.method))
                    # 使用增强版SSRF测试（支持DNSLog）
                    endpoint_findings.extend(enhanced_tester.test_ssrf_with_dnslog(endpoint.url, params, endpoint.method))
                    endpoint_findings.extend(tester.test_xxe(endpoint.url, params, endpoint.method))
                    endpoint_findings.extend(tester.test_command_injection(endpoint.url, params, endpoint.method))
                    endpoint_findings.extend(tester.test_path_traversal(endpoint.url, params, endpoint.method))
                    endpoint_findings.extend(tester.test_ssti(endpoint.url, params, endpoint.method))
                    endpoint_findings.extend(tester.test_ldap_injection(endpoint.url, params, endpoint.method))
                    endpoint_findings.extend(tester.test_no_sql_injection(endpoint.url, params, endpoint.method))
                
                if endpoint_findings:
                    logger.info(f"{Colors.ORANGE}[*] API {endpoint.url} 发现 {len(endpoint_findings)} 个潜在问题{Colors.END}")
                
                all_findings.extend(endpoint_findings)
            
            logger.info(f"{Colors.CYAN}[*] 测试爬取页面漏洞...{Colors.END}")
            page_extensions = ('.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.do', '.action', '')
            pages_to_test = []
            for page_url in self.crawled_pages:
                url_lower = page_url.lower()
                if any(url_lower.endswith(ext) for ext in page_extensions) and not url_lower.endswith(('.js', '.css', '.json', '.xml')):
                    pages_to_test.append(page_url)
            
            if pages_to_test:
                logger.info(f"{Colors.YELLOW}[*] 待测试页面数量: {len(pages_to_test)}{Colors.END}")
                page_tested = 0
                for page_url in pages_to_test[:20]:
                    page_tested += 1
                    logger.info(f"{Colors.YELLOW}[{page_tested}/{len(pages_to_test)}] 测试页面: {page_url[:80]}...{Colors.END}")
                    page_findings = tester.test_page_vulns(page_url)
                    if page_findings:
                        logger.info(f"{Colors.ORANGE}[*] 页面 {page_url} 发现 {len(page_findings)} 个潜在问题{Colors.END}")
                    all_findings.extend(page_findings)
            else:
                logger.info(f"{Colors.YELLOW}[-] 未发现可测试的页面{Colors.END}")
            
            logger.info(f"{Colors.CYAN}[*] 测试未授权访问...{Colors.END}")
            if sensitive_endpoints:
                logger.info(f"{Colors.YELLOW}[*] 敏感端点数量: {len(sensitive_endpoints)}{Colors.END}")
                unauthorized_findings = tester.test_unauthorized(sensitive_endpoints)
                all_findings.extend(unauthorized_findings)
                if unauthorized_findings:
                    logger.info(f"{Colors.ORANGE}[*] 发现 {len(unauthorized_findings)} 个未授权访问问题{Colors.END}")
            else:
                logger.info(f"{Colors.YELLOW}[-] 未发现敏感端点，跳过{Colors.END}")
            
            for r in all_findings:
                vuln_finding = VulnFinding(
                    url=r.url,
                    vuln_type=r.vuln_type,
                    severity=r.severity,
                    param=r.param,
                    payload=r.payload,
                    detail=r.detail,
                    evidence=getattr(r, 'evidence', ''),
                    request=getattr(r, 'request', ''),
                    response=getattr(r, 'response', '')
                )
                
                if self.add_vuln_finding(vuln_finding):
                    severity_color = {
                        "Critical": Colors.RED,
                        "High": Colors.ORANGE,
                        "Medium": Colors.YELLOW,
                        "Low": Colors.BLUE
                    }.get(r.severity, Colors.WHITE)
                    
                    vuln_type_cn = VULN_TYPE_MAP.get(r.vuln_type, r.vuln_type)
                    severity_cn = {
                        "Critical": "严重",
                        "High": "高危",
                        "Medium": "中危",
                        "Low": "低危"
                    }.get(r.severity, r.severity)
                    
                    logger.info(f"{severity_color}[!] 确认漏洞: {vuln_type_cn} ({severity_cn}){Colors.END}")
                    logger.info(f"    URL: {r.url}")
                    logger.info(f"    参数: {r.param}")
                    logger.info(f"    Payload: {r.payload}")
                    logger.info(f"    详情: {r.detail}")
                    
                    # 显示请求包和响应包
                    if getattr(r, 'request', ''):
                        logger.info(f"    {Colors.CYAN}--- 请求包 ---{Colors.END}")
                        for line in r.request.split('\n')[:20]:  # 限制显示行数
                            logger.info(f"    {line}")
                    if getattr(r, 'response', ''):
                        logger.info(f"    {Colors.CYAN}--- 响应包(前500字符) ---{Colors.END}")
                        response_preview = r.response[:500] if len(r.response) > 500 else r.response
                        for line in response_preview.split('\n')[:10]:
                            logger.info(f"    {line}")
            
            logger.info(f"{Colors.GREEN}[+] 漏洞测试完成，发现 {len(all_findings)} 个问题{Colors.END}")
            
            logger.info(f"{Colors.CYAN}[*] 测试页面链接漏洞...{Colors.END}")
            if not self.crawled_pages:
                logger.info(f"{Colors.YELLOW}[-] 未发现页面链接，跳过{Colors.END}")
            else:
                page_count = len(self.crawled_pages)
                logger.info(f"{Colors.YELLOW}[*] 待测试页面数量: {page_count}{Colors.END}")
                
                tested_page_count = 0
                for page_url in self.crawled_pages:
                    page_lower = page_url.lower()
                    if page_lower.endswith(static_extensions) or '.min.' in page_lower:
                        continue
                    
                    tested_page_count += 1
                    logger.info(f"{Colors.YELLOW}[{tested_page_count}/{page_count}] 测试页面: {page_url}{Colors.END}")
                    
                    page_findings = []
                    parsed = urlparse(page_url)
                    query_params = parse_qs(parsed.query)
                    
                    if query_params:
                        params = {p: "test" for p in query_params.keys()}
                        page_findings.extend(tester.test_sqli(page_url, params, "GET"))
                        page_findings.extend(tester.test_xss(page_url, params, "GET"))
                        page_findings.extend(tester.test_lfi(page_url, params, "GET"))
                        page_findings.extend(tester.test_rce(page_url, params, "GET"))
                    
                    if page_findings:
                        logger.info(f"{Colors.ORANGE}[*] 页面 {page_url} 发现 {len(page_findings)} 个潜在问题{Colors.END}")
                    
                    all_findings.extend(page_findings)
            
            # 云安全测试
            logger.info(f"{Colors.CYAN}[*] 测试云安全...{Colors.END}")
            try:
                from vuln_test import CloudSecurityTester
                cloud_tester = CloudSecurityTester(self.session, self.timeout)
                
                # 测试所有爬取的页面和JS文件
                cloud_targets = list(self.crawled_pages)[:30]
                js_files = list(self.js_files)[:20]
                
                cloud_findings = []
                
                # 测试页面内容
                for target_url in cloud_targets:
                    try:
                        r = self.session.get(target_url, timeout=10)
                        findings = cloud_tester.test_cloud_security(target_url, r.text)
                        cloud_findings.extend(findings)
                    except:
                        pass
                
                # 测试JS文件内容
                for js_url in js_files:
                    try:
                        r = self.session.get(js_url, timeout=10)
                        findings = cloud_tester.test_cloud_security(js_url, r.text)
                        cloud_findings.extend(findings)
                    except:
                        pass
                
                # 添加云安全发现到结果
                for r in cloud_findings:
                    vuln_finding = VulnFinding(
                        url=r.url,
                        vuln_type=r.vuln_type,
                        severity=r.severity,
                        param=r.param,
                        payload=r.payload,
                        detail=r.detail,
                        evidence=getattr(r, 'evidence', ''),
                        request=getattr(r, 'request', ''),
                        response=getattr(r, 'response', '')
                    )
                    
                    if self.add_vuln_finding(vuln_finding):
                        severity_color = {
                            "Critical": Colors.RED,
                            "High": Colors.ORANGE,
                            "Medium": Colors.YELLOW,
                            "Low": Colors.BLUE
                        }.get(r.severity, Colors.WHITE)
                        
                        vuln_type_cn = VULN_TYPE_MAP.get(r.vuln_type, r.vuln_type)
                        severity_cn = {
                            "Critical": "严重",
                            "High": "高危",
                            "Medium": "中危",
                            "Low": "低危"
                        }.get(r.severity, r.severity)
                        
                        logger.info(f"{severity_color}[!] 确认云安全漏洞: {vuln_type_cn} ({severity_cn}){Colors.END}")
                        logger.info(f"    URL: {r.url}")
                        logger.info(f"    详情: {r.detail}")
                
                if cloud_findings:
                    logger.info(f"{Colors.ORANGE}[*] 发现 {len(cloud_findings)} 个云安全问题{Colors.END}")
                else:
                    logger.info(f"{Colors.YELLOW}[-] 未发现云安全问题{Colors.END}")
                    
            except Exception as e:
                logger.debug(f"Cloud security test error: {e}")

    def fetch(self, url: str, retry: int = 3) -> Optional[str]:
        if url in self.visited_urls:
            logger.debug(f"URL already visited: {url}")
            return None
        self.visited_urls.add(url)
        
        logger.debug(f"[fetch] Getting: {url}")
        
        for attempt in range(retry):
            try:
                kwargs = {
                    'timeout': (self.timeout, self.timeout),
                    'verify': False,
                    'headers': self.headers,
                    'stream': True
                }
                if self.proxy:
                    kwargs['proxies'] = self.proxy
                
                resp = requests.get(url, **kwargs)
                logger.debug(f"[fetch] Status {resp.status_code}: {url}")
                
                if resp.status_code == 200:
                    content = resp.text
                    content_length = len(content)
                    logger.info(f"{Colors.CYAN}[*] 获取JS文件: {content_length/1024:.1f} KB{Colors.END}")
                    return content
                elif resp.status_code in [301, 302]:
                    location = resp.headers.get('Location')
                    if location:
                        return self.fetch(location)
                elif resp.status_code == 403:
                    logger.warning(f"403 禁止访问: {url}")
                else:
                    logger.debug(f"状态码 {resp.status_code}: {url}")
            except requests.exceptions.Timeout:
                logger.warning(f"请求超时: {url}")
                if attempt < retry - 1:
                    time.sleep(1)
            except Exception as e:
                logger.warning(f"请求错误 {url}: {type(e).__name__}")
                if attempt < retry - 1:
                    time.sleep(1)
        return None

    def get_page_js(self, url: str) -> List[str]:
        js_files = []
        
        if url in self.visited_urls:
            logger.debug(f"URL already visited, using cached content")
            return js_files
        
        try:
            html = self._fetch_content(url)
            if not html:
                logger.warning(f"无法获取页面: {url}")
                return js_files
            
            logger.info(f"获取到HTML长度: {len(html)} 字符")
            
            script_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'
            matches = re.findall(script_pattern, html, re.I)
            
            logger.info(f"初步匹配到 {len(matches)} 个JS引用")
            
            if not matches:
                script_pattern2 = r'<script[^>]+src=["\']?([^"\'>\s]+\.js)["\']?'
                matches = re.findall(script_pattern2, html, re.I)
                logger.info(f"备用模式匹配到 {len(matches)} 个JS引用")
            
            for src in matches:
                if not src or '.js' not in src.lower():
                    continue
                if src.startswith('http'):
                    js_files.append(src)
                elif src.startswith('//'):
                    js_files.append('https:' + src)
                else:
                    js_files.append(urljoin(url, src))
                    
            inline_scripts = re.findall(r'<script[^>]*>([\s\S]*?)</script>', html, re.I)
            if inline_scripts:
                for inline in inline_scripts:
                    # 过滤条件：长度>100，包含function，且不能包含太多HTML标签
                    if len(inline) > 100 and 'function' in inline.lower():
                        # 检查是否包含HTML标签（排除script标签本身）
                        html_tags = re.findall(r'<(?!script|/script)[a-zA-Z][^>]*>', inline)
                        html_tag_ratio = len(html_tags) / max(len(inline) / 100, 1)
                        # 如果HTML标签比例过高（每100字符超过2个标签），则跳过
                        if html_tag_ratio > 2:
                            continue
                        # 检查是否包含明显的非JS内容（如大量HTML实体）
                        if inline.count('&') > 10 or inline.count('<') > 20:
                            continue
                        # 清理内容，提取纯JS代码
                        clean_inline = re.sub(r'<[^>]+>', '', inline)
                        clean_inline = re.sub(r'\s+', ' ', clean_inline).strip()
                        if len(clean_inline) > 50:
                            js_files.append(f"inline:{len(js_files)}:{hash(clean_inline)}:{clean_inline[:500]}")
                
        except Exception as e:
            logger.error(f"解析JS出错 {url}: {e}")
            
        return list(set(js_files))
    
    def _fetch_content(self, url: str) -> Optional[str]:
        logger.debug(f"[_fetch_content] Fetching: {url}")
        for attempt in range(3):
            try:
                kwargs = {
                    'timeout': self.timeout,
                    'verify': False,
                    'headers': self.headers
                }
                if self.proxy:
                    kwargs['proxies'] = self.proxy
                    
                resp = requests.get(url, **kwargs)
                logger.debug(f"[_fetch_content] Status {resp.status_code}: {url}")
                if resp.status_code == 200:
                    return resp.text
                elif resp.status_code in [301, 302]:
                    location = resp.headers.get('Location')
                    if location:
                        return self._fetch_content(location)
            except Exception as e:
                logger.debug(f"[_fetch_content] Error: {e}")
                if attempt < 2:
                    time.sleep(1)
        return None

    def _fetch_page_info(self, url: str) -> Dict:
        """获取页面详细信息，包括状态码、内容长度、标题等"""
        result = {
            'content': None,
            'status_code': 0,
            'content_length': 0,
            'title': '未知',
            'headers': {},
            'cookies': {}
        }
        
        for attempt in range(3):
            try:
                kwargs = {
                    'timeout': self.timeout,
                    'verify': False,
                    'headers': self.headers
                }
                if self.proxy:
                    kwargs['proxies'] = self.proxy
                    
                resp = requests.get(url, **kwargs)
                result['status_code'] = resp.status_code
                result['headers'] = dict(resp.headers)
                result['cookies'] = dict(resp.cookies)
                
                # 获取内容（无论状态码）
                content = resp.text
                result['content'] = content if resp.status_code == 200 else None
                result['content_length'] = len(content)
                
                # 提取页面标题（无论状态码，只要有内容）
                if content:
                    try:
                        from bs4 import BeautifulSoup
                        soup = BeautifulSoup(content, 'html.parser')
                        title_tag = soup.find('title')
                        if title_tag and title_tag.string:
                            result['title'] = title_tag.string.strip()[:50]  # 限制长度
                    except:
                        pass
                
                if resp.status_code == 200:
                    return result
                elif resp.status_code in [301, 302]:
                    location = resp.headers.get('Location')
                    if location:
                        return self._fetch_page_info(location)
                    
                elif resp.status_code in [301, 302]:
                    location = resp.headers.get('Location')
                    if location:
                        return self._fetch_page_info(location)
                        
            except Exception as e:
                logger.debug(f"[_fetch_page_info] Error: {e}")
                if attempt < 2:
                    time.sleep(1)
                    
        return result

    def extract_endpoints(self, js_content: str, js_url: str) -> List[Endpoint]:
        endpoints = []
        seen_paths: Set[Tuple[str, str]] = set()  # 用于去重
        
        for pattern_info in self.endpoint_patterns:
            pattern = pattern_info["pattern"]
            method = pattern_info.get("method", "GET")
            group = pattern_info.get("group", 1)
            
            try:
                for match in re.finditer(pattern, js_content):
                    if pattern_info.get("method") == "group":
                        path = match.group(group)
                        method = match.group(pattern_info["method_group"]).upper()
                    else:
                        path = match.group(group)
                    
                    if not path or len(path) > 500:
                        continue
                    
                    filter_patterns = [
                        r'^[\.\#\-\_]?[\w]+$',
                        r'^el\-',
                        r'^chunk\-',
                        r'^focusing$',
                        r'^current[\-\_]?',
                        r'^is\-[\w]+$',
                        r'^innerHTML',
                        r'^outerHTML',
                        r'^range$',
                        r'^available$',
                        r'^today$',
                        r'^default$',
                        r'^selected$',
                        r'^disabled$',
                        r'^tab[\-\_]?',
                        r'^span$',
                        r'^col[\-\_]?',
                        r'^avatar[\-\_]?',
                        r'^carousel[\-\_]?',
                        r'^indicators[\-\_]?',
                        r'^expand[\-\_]?',
                        r'^leaf$',
                        r'^level[\-\_]?',
                        r'^row[\-\_]?',
                        r'^path\s',
                        r'^\s*<path',
                        r'^am\-',
                        r'^am[\w]+',
                        r'^webkit',
                        r'^moz',
                        r'^o[\w]+',
                        r'^on[A-Z]',
                        r'^set[A-Z]',
                        r'^get[A-Z]',
                        r'^request[A-Z]',
                        r'^(emulate|transition|animation|mutation|observer)',
                        r'^to[A-Z]',
                        r'^create[A-Z]',
                        r'^trigger[A-Z]',
                        r'^parse[A-Z]',
                        r'^is[A-Z]',
                        r'^has[A-Z]',
                        r'^offset',
                        r'^scroll',
                        r'^client',
                        r'^screen',
                        r'^navigator',
                        r'^document',
                        r'^window',
                        r'^location',
                        r'^history',
                        r'^localStorage',
                        r'^sessionStorage',
                        r'^Cookie',
                        r'^Mutation',
                        r'^Animation',
                        r'^Transition',
                        r'^Frame',
                        r'^Element',
                        r'^Attribute',
                        r'^Event',
                        r'^Handler',
                        r'^Listener',
                        r'^Callback',
                        r'^Promise',
                        r'^fetch\(',
                        r'^XMLHttp',
                        r'^FormData',
                        r'^Blob',
                        r'^FileReader',
                    ]
                    if any(re.match(p, path, re.IGNORECASE) for p in filter_patterns):
                        continue
                    
                    if len(path) < 3:
                        continue
                    
                    # 清理路径中的引号
                    path = path.strip("'\"")
                    
                    # 标准化端点路径（返回相对路径形式，便于展示和去重）
                    if path.startswith('http'):
                        # 从完整URL提取路径
                        parsed = urlparse(path)
                        endpoint_path = parsed.path if parsed.path else '/'
                    elif path.startswith('//'):
                        # 从协议相对URL提取路径
                        parsed = urlparse('https:' + path)
                        endpoint_path = parsed.path if parsed.path else '/'
                    elif path.startswith('/'):
                        # 根路径，直接使用
                        endpoint_path = path
                    elif path.startswith('./') or path.startswith('../'):
                        # 相对路径，尝试解析为绝对路径
                        endpoint_path = self._resolve_relative_path(path, js_url)
                    else:
                        # 其他情况，添加 / 前缀
                        endpoint_path = '/' + path
                    
                    # 过滤过短的路径
                    if len(endpoint_path) < 2:
                        continue
                    
                    # 去重检查
                    path_key = (endpoint_path, method)
                    if path_key in seen_paths:
                        continue
                    seen_paths.add(path_key)
                    
                    # 评估风险
                    risk_level, risks = self._assess_endpoint_risk(endpoint_path, method)
                    
                    # 判断路径类型
                    is_absolute = endpoint_path.startswith('/') and not endpoint_path.startswith('./') and not endpoint_path.startswith('../')
                    is_module = endpoint_path.startswith('./') or endpoint_path.startswith('../') or '.js' in path.lower()
                    is_route = bool(re.search(r'\.(do|action|jsp|php|aspx|vue|react)$', endpoint_path, re.I))
                    
                    api_type = self._get_api_type_from_url(endpoint_path)
                    
                    endpoints.append(Endpoint(
                        url=endpoint_path, 
                        method=method, 
                        source_js=js_url, 
                        risk_level=risk_level, 
                        risks=risks,
                        api_type=api_type,
                        is_absolute=is_absolute,
                        is_module=is_module,
                        is_route=is_route
                    ))
            except Exception as e:
                logger.debug(f"Pattern error: {e}")
        
        return endpoints
    
    def _verify_endpoint_exists(self, endpoint, source_url: str) -> bool:
        """
        验证端点是否真实存在
        通过发送HEAD请求检查端点是否返回有效响应
        """
        try:
            # 构建完整URL
            if endpoint.url.startswith('http'):
                test_url = endpoint.url
            else:
                parsed = urlparse(source_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                test_url = base_url + endpoint.url
            
            # 发送HEAD请求验证
            resp = self.session.head(test_url, timeout=5, allow_redirects=True)
            
            # 如果HEAD请求成功（2xx或3xx），认为端点存在
            if resp.status_code < 400:
                return True
            
            # 如果HEAD返回405（Method Not Allowed），尝试GET请求
            if resp.status_code == 405:
                resp = self.session.get(test_url, timeout=5, allow_redirects=True)
                if resp.status_code < 400:
                    return True
            
            # 检查是否是常见的"页面不存在"响应
            if resp.status_code in [404, 410]:
                return False
            
            # 其他情况（如401, 403等）可能表示端点存在但受保护
            return True
            
        except Exception as e:
            logger.debug(f"验证端点失败 {endpoint.url}: {e}")
            # 验证失败时，默认保留端点（保守策略）
            return True
    
    def _resolve_relative_path(self, relative_path: str, base_url: str) -> str:
        """
        解析相对路径为绝对路径
        支持 ./ ../ 和字符串拼接路径
        """
        try:
            # 如果base_url是内联脚本，无法解析，保持原样
            if base_url.startswith('inline:'):
                return relative_path
            
            # 使用urljoin解析相对路径
            resolved = urljoin(base_url, relative_path)
            parsed = urlparse(resolved)
            
            # 返回路径部分
            return parsed.path if parsed.path else '/'
        except Exception as e:
            logger.debug(f"解析相对路径失败 {relative_path} from {base_url}: {e}")
            return relative_path
    
    def _extract_js_string_concatenation(self, js_content: str) -> List[str]:
        """
        提取JS中的字符串拼接路径
        例如: var base = '/v1'; var url = base + '/user'
        """
        paths = []
        
        # 匹配 base + '/path' 或 base + "/path" 模式
        concat_patterns = [
            # var url = base + '/api/user'
            r'["\']?([\w_]+)["\']?\s*\+\s*["\'](/[^"\']+)["\']',
            # var url = '/api' + '/user'
            r'["\'](/[^"\']+)["\']\s*\+\s*["\'](/[^"\']+)["\']',
            # var url = `${base}/api/user`
            r'\$\{([^}]+)\}(/[^`\']+)',
            # baseUrl + endpoint
            r'(base[_\-]?[Uu]rl|api[_\-]?[Uu]rl|root[_\-]?[Uu]rl)\s*\+\s*["\'](/[^"\']+)["\']',
        ]
        
        for pattern in concat_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, tuple):
                    # 组合路径
                    if len(match) >= 2:
                        combined = match[0] + match[1] if match[0].startswith('/') else match[1]
                        paths.append(combined)
                else:
                    paths.append(match)
        
        return paths
    
    def _filter_static_endpoints(self, endpoints: List[Endpoint]) -> List[Endpoint]:
        static_extensions = (
            '.css', '.scss', '.sass', '.less', '.map',
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp',
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            '.mp4', '.webm', '.ogg', '.mp3', '.wav', '.flac',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.json', '.xml', '.yml', '.yaml'
        )
        
        filtered = []
        for ep in endpoints:
            url_lower = ep.url.lower()
            path = urlparse(ep.url).path.lower()
            
            if path.endswith(static_extensions):
                continue
            
            if any(url_lower.endswith(ext) for ext in static_extensions):
                continue
            
            if '/static/' in path or '/assets/' in path or '/public/' in path:
                if any(ext in path for ext in ['.png', '.jpg', '.svg', '.woff', '.css']):
                    continue
            
            filtered.append(ep)
        
        return filtered
    
    def _filter_page_routes(self, endpoints: List[Endpoint]) -> List[Endpoint]:
        api_patterns = [
            '/api/', '/rest/', '/v1/', '/v2/', '/v3/', '/v4/',
            '/rpc/', '/graphql', '/ws/', '/socket/',
            '/ajax/', '/json/', '/svc/', '/service/',
            '/data/', '/query/', '/exec/', '/rpc/',
            '.json', '.xml', '.do', '.action', '.jsp', '.php', '.aspx'
        ]
        
        filtered = []
        for ep in endpoints:
            path = urlparse(ep.url).path.lower()
            
            if any(pattern in path for pattern in api_patterns):
                filtered.append(ep)
                ep.is_route = False
                continue
            
            path_parts = [p for p in path.split('/') if p]
            if len(path_parts) >= 2 and path_parts[0] in ['api', 'rest', 'v1', 'v2', 'v3', 'v4', 'services', 'data']:
                filtered.append(ep)
                ep.is_route = False
                continue
            
            if '?' in ep.url and any(kw in path for kw in ['id', 'token', 'user', 'data', 'query', 'search', 'list', 'get', 'fetch', 'page', 'size', 'limit', 'offset', 'sort', 'order', 'filter', 'keyword', 'key', 'value', 'name', 'type', 'action', 'do', 'add', 'edit', 'delete', 'save', 'update', 'remove', 'create', 'modify']):
                filtered.append(ep)
                ep.is_route = False
                continue
            
            common_api_paths = ['/login', '/logout', '/register', '/auth', '/user', '/admin', '/manage', '/system', '/config', '/upload', '/download', '/export', '/import', '/file', '/menu', '/role', '/permission', '/log', '/dict', '/dept', '/job', '/notice', '/monitor', '/tool', '/generator', '/build', '/captcha', '/sms', '/email', '/verify', '/code', '/send', '/get', '/post', '/set']
            if any(p in path for p in common_api_paths):
                filtered.append(ep)
                ep.is_route = False
                continue
            
            ep.is_route = True
            filtered.append(ep)
        
        return filtered

    def _is_relative_path(self, path: str) -> bool:
        return not path.startswith(('http://', 'https://', '//', 'data:'))

    def _get_api_type_from_url(self, url: str) -> str:
        if not url:
            return "通用接口"
        
        url_lower = url.lower()
        
        try:
            path = urlparse(url).path.lower()
        except Exception:
            path = ""
        
        api_type_map = {
            '/api/': 'REST API',
            '/rest/': 'REST API',
            '/graphql': 'GraphQL',
            '/rpc/': 'RPC接口',
            '/v1/': 'REST API v1',
            '/v2/': 'REST API v2',
            '/v3/': 'REST API v3',
            '/v4/': 'REST API v4',
            '/ajax/': 'Ajax接口',
            '/json/': 'JSON接口',
            '/data/': '数据接口',
            '/query/': '查询接口',
            '/search/': '搜索接口',
            '/auth/': '认证接口',
            '/login': '登录接口',
            '/user/': '用户接口',
            '/admin/': '管理接口',
            '/upload/': '上传接口',
            '/download/': '下载接口',
            '/ws/': 'WebSocket',
            '/socket/': 'WebSocket',
            '.json': 'JSON接口',
            '.do': 'Java接口',
            '.action': 'Struts接口',
            '.jsp': 'JSP接口',
            '.php': 'PHP接口',
            '.aspx': 'ASP.NET接口',
        }
        
        sorted_keywords = sorted(api_type_map.items(), key=lambda x: len(x[0]), reverse=True)
        
        for keyword, api_type in sorted_keywords:
            if keyword and keyword in path:
                return api_type
        
        for keyword, api_type in sorted_keywords:
            if keyword and keyword in url_lower:
                return api_type
        
        return "通用接口"

    def _assess_endpoint_risk(self, url: str, method: str = "GET") -> Tuple[str, List[str]]:
        path = urlparse(url).path.lower()
        risks = []
        risk_level = "Low"
        
        high_risk = ['/admin', '/manage', '/dashboard', '/config', '/settings', '/upload', '/download', '/root']
        auth_risk = ['/auth', '/login', '/oauth', '/token', '/sso', '/register', '/signup', '/reset']
        data_risk = ['/user', '/order', '/payment', '/money', '/card', '/account', '/profile', '/address']
        
        for keyword in high_risk:
            if keyword in path:
                risks.append(f"高风险路径: {keyword}")
                risk_level = "High"
                
        for keyword in auth_risk:
            if keyword in path:
                risks.append(f"认证相关: {keyword}")
                if risk_level == "Low":
                    risk_level = "Medium"
                    
        for keyword in data_risk:
            if keyword in path:
                risks.append(f"数据相关: {keyword}")
                
        if method in ['PUT', 'DELETE', 'PATCH']:
            risks.append(f"危险HTTP方法: {method}")
            
        return risk_level, risks

    def scan_sensitive_info(self, js_content: str, js_url: str) -> List[ScanResult]:
        findings = []
        
        parsed_url = urlparse(js_url)
        url_path = parsed_url.path
        
        content_lower = js_content.lower()
        category_context_cache = {}
        
        for category, rules in self.sensitive_patterns.items():
            strict_rules = []
            loose_rules = []
            
            for rule in rules:
                try:
                    compiled = re.compile(rule["pattern"], re.IGNORECASE)
                    has_explicit_prefix = self._has_explicit_prefix(rule["pattern"])
                    
                    rule_data = {"pattern": compiled, "rule": rule}
                    
                    if has_explicit_prefix:
                        strict_rules.append(rule_data)
                    else:
                        loose_rules.append(rule_data)
                except re.error:
                    pass
            
            for rule_data in strict_rules:
                pattern = rule_data["pattern"]
                rule = rule_data["rule"]
                
                search_text = url_path if rule.get("target") == "url" else js_content
                matches = list(pattern.finditer(search_text))
                
                for match in matches:
                    finding = match.group(0)
                    min_len = rule.get("min_len", 0)
                    
                    if min_len > 0 and len(finding) < min_len:
                        continue
                    
                    if len(finding) > 4 and len(finding) < 200:
                        findings.append(ScanResult(
                            url=js_url,
                            type=category,
                            severity=rule["severity"],
                            finding=f"{rule['name']}: {finding[:50]}",
                            detail=finding[:100],
                            source=js_url
                        ))
            
            for rule_data in loose_rules:
                pattern = rule_data["pattern"]
                rule = rule_data["rule"]
                context = rule.get("context", "")
                min_len = rule.get("min_len", 0)
                target = rule.get("target", "content")
                key_type = rule.get("key_type", "generic")
                
                if target == "url":
                    search_text = url_path
                    matches = list(pattern.finditer(search_text))
                else:
                    if context:
                        if not re.search(context, content_lower):
                            continue
                    search_text = js_content
                    matches = list(pattern.finditer(search_text))
                
                for match in matches:
                    finding = match.group(0)
                    match_start = match.start()
                    
                    if target == "content" and min_len > 0 and len(finding) < min_len:
                        continue
                    
                    if self._is_common_js_word(finding):
                        continue
                    
                    # 检查是否在注释中
                    if self._is_in_comment(js_content, match_start):
                        continue
                    
                    # 验证是否为真实密钥（熵值检查等）
                    is_real, reason = self._is_likely_real_key(finding, key_type)
                    if not is_real:
                        logger.debug(f"过滤可能的假密钥: {finding[:30]}... 原因: {reason}")
                        continue
                    
                    if len(finding) > 4 and len(finding) < 200:
                        findings.append(ScanResult(
                            url=js_url,
                            type=category,
                            severity=rule["severity"],
                            finding=f"{rule['name']}: {finding[:50]}",
                            detail=f"{finding[:100]}\n验证: {reason}",
                            source=js_url
                        ))
                        
        return findings
    
    def _has_explicit_prefix(self, pattern: str) -> bool:
        prefix_patterns = [
            r'^LTAI', r'^AKID', r'^TKE_', r'^QINIU', r'^AKIA', r'^ASIA',
            r'^AIza', r'^SG\.', r'^key-', r'^AK', r'^SK', r'^TKE_',
            r'^ghp_', r'^gho_', r'^ghu_', r'^ghs_', r'^xox',
            r'^npm_', r'^pypi-', r'^NtCloud-', r'^KSY-', r'^shpat_',
            r'^sq0atp-', r'^pk\.', r'^A20', r'^AP-',
        ]
        for prefix in prefix_patterns:
            if re.match(prefix, pattern, re.IGNORECASE):
                return True
        return False
    
    def _is_common_js_word(self, text: str) -> bool:
        common_words = {
            'webkit', 'moz', 'ms', 'o', 'chrome', 'safari', 'firefox', 'edge',
            'animation', 'transition', 'transform', 'requestanimationframe',
            'cancelanimationframe', 'mutationobserver', 'performance', 'timing',
            'fullscreen', 'visibility', 'pointer', 'touch', 'animationend',
            'transitionend', 'animationstart', 'animationiteration',
            'keyframes', 'stylesheet', 'cssrules', 'createelement',
            'getelement', 'queryselector', 'getcomputedstyle', 'addeventlistener',
            'removeeventlistener', 'dispatchevent', 'preventdefault',
            'stoppropagation', 'innerhtml', 'outerhtml', 'textcontent',
            'children', 'parentnode', 'childnodes', 'firstchild', 'lastchild',
            'nextsibling', 'previoussibling', 'appendchild', 'removechild',
            'insertbefore', 'cloneNode', 'setattribute', 'getattribute',
            'classname', 'classlist', 'style', 'dataset', 'scroll', 'scrollto',
            'scrollby', 'scrollintoview', 'getboundingclientrect', 'offset',
            'client', 'scroll', 'inner', 'outer', 'document', 'window', 'element',
            'node', 'event', 'target', 'currenttarget', 'relatedtarget',
            'keycode', 'which', 'button', 'buttons', 'clientx', 'clienty',
            'pagex', 'pagey', 'screenx', 'screeny', 'movementx', 'movementy',
            'deltax', 'deltay', 'deltaz', 'deltamode', 'wheel', 'mouse',
            'keyboard', 'touch', 'pointer', 'focus', 'blur', 'change', 'input',
            'submit', 'reset', 'select', 'copy', 'cut', 'paste', 'drag', 'drop',
            'contextmenu', 'resize', 'scroll', 'zoom', 'rotate', 'gesture',
            'orientation', 'deviceorientation', 'devicemotion', 'geolocation',
            'notification', 'permission', 'storage', 'local', 'session',
            'indexeddb', 'websql', 'cookie', 'cache', 'worker', 'serviceworker',
            'sharedworker', 'websocket', 'xmlhttprequest', 'fetch', 'promise',
            'async', 'await', 'generator', 'iterator', 'symbol', 'proxy',
            'reflect', 'map', 'set', 'weakmap', 'weakset', 'array', 'object',
            'function', 'string', 'number', 'boolean', 'null', 'undefined',
            'nan', 'infinity', 'math', 'date', 'regexp', 'error', 'typeerror',
            'rangeerror', 'syntaxerror', 'referenceerror', 'urierror',
            'evalerror', 'json', 'parse', 'stringify', 'encodeuri', 'decodeuri',
            'encodeuricomponent', 'decodeuricomponent', 'escape', 'unescape',
            'eval', 'isnan', 'isfinite', 'parseint', 'parsefloat', 'nan',
            'prototype', 'constructor', 'hasownproperty', 'isprototypeof',
            'propertyisenumerable', 'tostring', 'tolocalestring', 'valueof',
            'apply', 'call', 'bind', 'arguments', 'caller', 'length', 'name',
            'message', 'stack', 'throw', 'try', 'catch', 'finally', 'debugger',
        }
        text_lower = text.lower()
        for word in common_words:
            if text_lower == word or text_lower.startswith(word + '_') or text_lower.startswith(word + 's'):
                return True
            if text_lower.endswith(word) or text_lower.endswith(word + 's'):
                return True
        if re.match(r'^webkit[A-Z]', text) or re.match(r'^moz[A-Z]', text):
            return True
        if re.match(r'^ms[A-Z]', text) or re.match(r'^o[A-Z]', text):
            return True
        return False
    
    def _calculate_entropy(self, text: str) -> float:
        """
        计算字符串的熵值（香农熵）
        用于判断密钥的随机性
        返回值: 0-8之间，越高表示越随机（越可能是真实密钥）
        """
        if not text or len(text) < 4:
            return 0.0
        
        # 计算字符频率
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # 计算熵
        entropy = 0.0
        text_len = len(text)
        for count in char_counts.values():
            if count > 0:
                freq = count / text_len
                entropy -= freq * math.log2(freq)
        
        return entropy
    
    def _is_likely_real_key(self, text: str, key_type: str = "generic") -> Tuple[bool, str]:
        """
        判断发现的密钥是否可能是真实密钥（而非示例/假数据）
        
        Returns:
            (is_real, reason)
        """
        text_lower = text.lower()
        
        # 1. 检查是否为明显的示例数据
        example_patterns = [
            r'example', r'sample', r'test', r'demo', r'fake', r'dummy',
            r'placeholder', r'your[_-]?key', r'your[_-]?token', r'your[_-]?secret',
            r'xxx', r'aaaa', r'bbbb', r'cccc', r'1111', r'0000', r'12345',
            r'insert[_-]?here', r'replace[_-]?me', r'changeme', r'mykey',
        ]
        
        for pattern in example_patterns:
            if re.search(pattern, text_lower):
                return False, "包含示例数据标识"
        
        # 2. 检查熵值（随机性）
        entropy = self._calculate_entropy(text)
        
        # 不同类型密钥的熵值阈值
        entropy_thresholds = {
            "aws_access_key": 3.5,
            "aws_secret_key": 4.0,
            "api_key": 3.0,
            "jwt_token": 4.5,
            "generic": 3.0
        }
        
        threshold = entropy_thresholds.get(key_type, 3.0)
        
        if entropy < threshold:
            return False, f"熵值过低({entropy:.2f} < {threshold})，可能是假数据"
        
        # 3. 长度检查
        if len(text) < 16:
            return False, "长度过短"
        
        # 4. 字符分布检查（真实密钥通常有混合字符）
        has_lower = bool(re.search(r'[a-z]', text))
        has_upper = bool(re.search(r'[A-Z]', text))
        has_digit = bool(re.search(r'\d', text))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', text))
        
        variety_score = sum([has_lower, has_upper, has_digit, has_special])
        
        if variety_score < 2:
            return False, "字符种类过少，缺乏随机性"
        
        # 5. 重复模式检查
        if re.search(r'(.)\1{3,}', text):  # 连续4个相同字符
            return False, "存在重复模式"
        
        return True, f"熵值:{entropy:.2f}, 字符种类:{variety_score}"
    
    def _is_in_comment(self, content: str, match_start: int) -> bool:
        """检查匹配位置是否在注释中"""
        # 简单检查：查找最近的注释标记
        before_text = content[:match_start]
        
        # 检查是否在 // 注释中
        last_line_start = before_text.rfind('\n')
        if last_line_start == -1:
            last_line_start = 0
        last_line = before_text[last_line_start:]
        if '//' in last_line:
            return True
        
        # 检查是否在 /* */ 注释中
        last_block_start = before_text.rfind('/*')
        last_block_end = before_text.rfind('*/')
        if last_block_start > last_block_end:
            return True
        
        # 检查是否在 <!-- --> 注释中（HTML）
        last_html_start = before_text.rfind('<!--')
        last_html_end = before_text.rfind('-->')
        if last_html_start > last_html_end:
            return True
        
        return False

    def deobfuscate_js(self, js_content: str) -> str:
        """
        简单的JS代码混淆还原
        处理常见的混淆模式：eval(atob(...)), String.fromCharCode等
        """
        decoded = js_content
        max_iterations = 5  # 防止无限循环
        
        for _ in range(max_iterations):
            original = decoded
            
            # 1. 解码 eval(atob('...')) 模式
            eval_atob_pattern = r'eval\s*\(\s*atob\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']\s*\)\s*\)'
            for match in re.finditer(eval_atob_pattern, decoded):
                try:
                    encoded = match.group(1)
                    decoded_str = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                    decoded = decoded.replace(match.group(0), decoded_str)
                except:
                    pass
            
            # 2. 解码 atob('...') 模式
            atob_pattern = r'atob\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']\s*\)'
            for match in re.finditer(atob_pattern, decoded):
                try:
                    encoded = match.group(1)
                    decoded_str = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                    decoded = decoded.replace(match.group(0), f'"{decoded_str}"')
                except:
                    pass
            
            # 3. 解码 String.fromCharCode(...) 模式
            charcode_pattern = r'String\.fromCharCode\s*\(([^)]+)\)'
            for match in re.finditer(charcode_pattern, decoded):
                try:
                    codes_str = match.group(1)
                    # 提取数字
                    codes = [int(c.strip()) for c in codes_str.split(',') if c.strip().isdigit()]
                    decoded_str = ''.join(chr(c) for c in codes)
                    decoded = decoded.replace(match.group(0), f'"{decoded_str}"')
                except:
                    pass
            
            # 4. 解码 \x 十六进制转义
            hex_pattern = r'\\x([0-9a-fA-F]{2})'
            def replace_hex(m):
                try:
                    return chr(int(m.group(1), 16))
                except:
                    return m.group(0)
            decoded = re.sub(hex_pattern, replace_hex, decoded)
            
            # 5. 解码 \u Unicode转义
            unicode_pattern = r'\\u([0-9a-fA-F]{4})'
            def replace_unicode(m):
                try:
                    return chr(int(m.group(1), 16))
                except:
                    return m.group(0)
            decoded = re.sub(unicode_pattern, replace_unicode, decoded)
            
            # 如果没有变化，退出循环
            if decoded == original:
                break
        
        return decoded

    def detect_dom_xss(self, js_content: str, js_url: str) -> List[VulnFinding]:
        """
        检测DOM型XSS漏洞
        通过分析JS代码中的source到sink的数据流
        """
        findings = []
        
        # DOM XSS Sources (用户可控输入)
        sources = [
            'location.href', 'location.search', 'location.hash', 'location.pathname',
            'document.URL', 'document.documentURI', 'document.baseURI',
            'window.name', 'document.referrer',
            'localStorage.getItem', 'sessionStorage.getItem',
        ]
        
        # DOM XSS Sinks (危险输出点)
        sinks = {
            'innerHTML': 'high',
            'outerHTML': 'high',
            'document.write': 'high',
            'document.writeln': 'high',
            'eval': 'critical',
            'setTimeout': 'medium',
            'setInterval': 'medium',
            'location.href': 'medium',
            'location.replace': 'medium',
            'location.assign': 'medium',
            'window.open': 'medium',
            'script.src': 'high',
            'iframe.src': 'medium',
            'form.action': 'low',
        }
        
        # 检测直接的source到sink的赋值
        for sink, severity in sinks.items():
            # 匹配 sink = source 或 sink(source) 模式
            if '.' in sink:
                obj, prop = sink.rsplit('.', 1)
                # 匹配 element.innerHTML = location.hash
                pattern = rf'{obj}\.{prop}\s*=\s*([^;]+)'
                for match in re.finditer(pattern, js_content, re.I):
                    assigned_value = match.group(1).strip()
                    # 检查赋值是否包含source
                    for source in sources:
                        if source in assigned_value:
                            # 检查是否有 sanitization
                            if not self._has_sanitization(assigned_value):
                                findings.append(VulnFinding(
                                    url=js_url,
                                    vuln_type="DOM XSS",
                                    severity=severity.upper(),
                                    param=source,
                                    payload=sink,
                                    detail=f"{sink} 直接赋值来自 {source}，无过滤: {assigned_value[:50]}"
                                ))
            else:
                # 函数调用如 eval(source)
                pattern = rf'{sink}\s*\(\s*([^)]+)\s*\)'
                for match in re.finditer(pattern, js_content, re.I):
                    arg = match.group(1).strip()
                    for source in sources:
                        if source in arg:
                            if not self._has_sanitization(arg):
                                findings.append(VulnFinding(
                                    url=js_url,
                                    vuln_type="DOM XSS",
                                    severity=severity.upper(),
                                    param=source,
                                    payload=sink,
                                    detail=f"{sink}() 调用包含 {source}，无过滤: {arg[:50]}"
                                ))
        
        # 检测 jQuery 相关的DOM XSS
        jquery_sinks = [
            (r'\$\s*\(\s*["\']\s*<[^>]+>[^<]*["\']\s*\)\s*\.\s*appendTo\s*\(\s*["\']?body["\']?\s*\)', 'high'),
            (r'\.html\s*\(\s*([^)]+)\s*\)', 'high'),
            (r'\.append\s*\(\s*([^)]+)\s*\)', 'medium'),
            (r'\.prepend\s*\(\s*([^)]+)\s*\)', 'medium'),
        ]
        
        for pattern, severity in jquery_sinks:
            for match in re.finditer(pattern, js_content, re.I):
                arg = match.group(1) if match.groups() else ""
                for source in sources:
                    if source in arg or source in js_content[max(0, match.start()-200):match.start()]:
                        if not self._has_sanitization(arg):
                            findings.append(VulnFinding(
                                url=js_url,
                                vuln_type="DOM XSS (jQuery)",
                                severity=severity.upper(),
                                param=source,
                                payload=match.group(0)[:50],
                                detail=f"jQuery操作包含用户输入，无过滤"
                            ))
                            break
        
        # 检测 React/Vue 的 dangerouslySetInnerHTML
        framework_patterns = [
            (r'dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\s*\}\s*\}', 'React dangerouslySetInnerHTML'),
            (r'v-html\s*=\s*["\']([^"\']+)["\']', 'Vue v-html'),
        ]
        
        for pattern, framework in framework_patterns:
            for match in re.finditer(pattern, js_content, re.I):
                content = match.group(1) if match.groups() else ""
                for source in sources:
                    if source in content:
                        findings.append(VulnFinding(
                            url=js_url,
                            vuln_type=f"DOM XSS ({framework})",
                            severity="HIGH",
                            param=source,
                            payload=match.group(0)[:50],
                            detail=f"{framework} 使用用户输入，可能导致XSS"
                        ))
                        break
        
        return findings
    
    def _has_sanitization(self, code: str) -> bool:
        """检查代码是否包含常见的过滤/转义操作"""
        sanitization_patterns = [
            r'escapeHtml', r'htmlspecialchars', r'sanitize', r'clean',
            r'DOMPurify', r'encodeURIComponent', r'escape\s*\(',
            r'replace\s*\(\s*/[<>"\']', r'replace\s*\(\s*["\']<[\"\']',
            r'innerText', r'textContent',
        ]
        return any(re.search(p, code, re.I) for p in sanitization_patterns)

    def detect_vulnerable_libs(self, js_content: str, js_url: str) -> List[ScanResult]:
        findings = []
        
        for lib_name, lib_info in self.vuln_libs.items():
            patterns = [
                rf'{lib_name}[/-]?v?(\d+\.\d+\.\d+)',
                rf'{lib_name}[/-]?(\d+\.\d+\.\d+)',
                rf'["\'](?:https?://[^"\']+)?(?:node_modules|/lib/|/dist/){lib_name}[/-]?v?(\d+\.\d+\.\d+)',
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, js_content, re.I)
                for version in matches:
                    if version and self._compare_version(version, lib_info["min_safe"]) < 0:
                        findings.append(ScanResult(
                            url=js_url,
                            type="vulnerable_library",
                            severity="High",
                            finding=f"{lib_name} {version}",
                            detail=f"存在已知漏洞: {', '.join(lib_info['cves']) if lib_info['cves'] else '版本过旧'}",
                            source=js_url
                        ))
                        
        return findings

    def _compare_version(self, v1: str, v2: str) -> int:
        try:
            parts1 = [int(x) for x in v1.split('.')[:3]]
            parts2 = [int(x) for x in v2.split('.')[:3]]
            
            for i in range(max(len(parts1), len(parts2))):
                p1 = parts1[i] if i < len(parts1) else 0
                p2 = parts2[i] if i < len(parts2) else 0
                if p1 > p2:
                    return 1
                elif p1 < p2:
                    return -1
            return 0
        except:
            return 0

    def analyze_dom_xss(self, js_content: str, js_url: str) -> List[ScanResult]:
        findings = []
        
        for vuln_type, data in self.dangerous_funcs.items():
            sinks = data.get("sinks", [])
            sources = data.get("sources", [])
            
            all_sinks_pos = {}
            for sink in sinks:
                for match in re.finditer(re.escape(sink), js_content):
                    if sink not in all_sinks_pos:
                        all_sinks_pos[sink] = []
                    all_sinks_pos[sink].append(match.start())
            
            for source in sources:
                for match in re.finditer(re.escape(source), js_content):
                    source_pos = match.start()
                    
                    for sink, sink_positions in all_sinks_pos.items():
                        for sink_pos in sink_positions:
                            if abs(sink_pos - source_pos) < 300:
                                start = max(0, min(source_pos, sink_pos) - 50)
                                end = min(len(js_content), max(source_pos, sink_pos) + 100)
                                code_snippet = js_content[start:end].replace('\n', ' ').strip()
                                
                                source_line_start = js_content.rfind('\n', 0, source_pos) + 1
                                source_line_end = js_content.find('\n', source_pos)
                                source_line = js_content[source_line_start:source_line_end].strip() if source_line_end != -1 else js_content[source_line_start:].strip()
                                
                                sink_line_start = js_content.rfind('\n', 0, sink_pos) + 1
                                sink_line_end = js_content.find('\n', sink_pos)
                                sink_line = js_content[sink_line_start:sink_line_end].strip() if sink_line_end != -1 else js_content[sink_line_start:].strip()
                                
                                findings.append(ScanResult(
                                    url=js_url,
                                    type=f"dom_{vuln_type.lower()}",
                                    severity="High",
                                    finding=f"{vuln_type}: {source} → {sink}",
                                    detail=f"Source位置: {source_pos} | Sink位置: {sink_pos}",
                                    source=js_url
                                ))
                                
                                findings.append(ScanResult(
                                    url=js_url,
                                    type=f"dom_{vuln_type.lower()}_code",
                                    severity="Medium",
                                    finding=f"{vuln_type}代码片段",
                                    detail=f"Source: {source_line[:100]} | Sink: {sink_line[:100]}",
                                    source=js_url
                                ))
                                break
                            
        return findings

    def check_sourcemap(self, js_url: str) -> Optional[ScanResult]:
        possible_maps = [
            js_url + '.map',
            js_url.replace('.js', '.js.map'),
            js_url.replace('/js/', '/js.map/'),
            js_url.replace('/bundle/', '/bundle.map/'),
            js_url.replace('/dist/', '/dist.map/'),
        ]
        
        for map_url in possible_maps:
            try:
                resp = requests.head(map_url, timeout=3, verify=False, headers=self.headers, allow_redirects=True)
                if resp.status_code == 200:
                    content_len = resp.headers.get('Content-Length', '0')
                    logger.debug(f"SourceMap check 200: {map_url} ({content_len} bytes)")
                    return ScanResult(
                        url=map_url,
                        type="sourcemap_leak",
                        severity="Medium",
                        finding=f"SourceMap文件泄露: {map_url}",
                        detail=f"可能泄露源码路径和原始代码",
                        source=js_url
                    )
            except Exception as e:
                logger.debug(f"SourceMap check error: {map_url} - {e}")
        return None
    
    def download_and_analyze_sourcemap(self, js_url: str, session: requests.Session) -> List[ScanResult]:
        findings = []
        possible_maps = [
            js_url + '.map',
            js_url.replace('.js', '.js.map'),
            js_url.replace('/js/', '/js.map/'),
            js_url.replace('/bundle/', '/bundle.map/'),
            js_url.replace('/dist/', '/dist.map/'),
        ]
        
        for map_url in possible_maps:
            try:
                resp = session.get(map_url, timeout=10, verify=False, headers=self.headers)
                if resp.status_code == 200 and 'json' in resp.headers.get('Content-Type', ''):
                    try:
                        sm_data = resp.json()
                        sources = sm_data.get('sources', [])
                        sourcesContent = sm_data.get('sourcesContent', [])
                        
                        logger.info(f"{Colors.CYAN}[*] 下载SourceMap成功: {map_url}, 包含 {len(sources)} 个源文件{Colors.END}")
                        
                        for i, source in enumerate(sources):
                            source_content = sourcesContent[i] if i < len(sourcesContent) else ""
                            
                            if source_content:
                                sensitive = self._scan_sourcemap_content(source_content, source, map_url)
                                findings.extend(sensitive)
                                
                                api_paths = self._extract_api_from_source(source_content, source, map_url)
                                for api in api_paths:
                                    if self.add_result(api):
                                        findings.append(api)
                                        
                    except json.JSONDecodeError:
                        pass
            except Exception as e:
                logger.debug(f"SourceMap download error: {map_url} - {e}")
        
        return findings
    
    def _scan_sourcemap_content(self, content: str, source_file: str, map_url: str) -> List[ScanResult]:
        findings = []
        
        cloud_keys = [
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (r'(?i)aws[_-]secret[_-]access[_-]key["\s:=]+[A-Za-z0-9/+=]{40}', 'AWS Secret Key'),
            (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key'),
            (r'SK[0-9a-fA-F]{32}', 'Stripe API Key'),
            (r'xox[baprs]-[0-9a-zA-Z]{10,48}', 'Slack Token'),
            (r'gh[pousr]_[A-Za-z0-9_]{36,255}', 'GitHub Token'),
            (r'["\'](sk|live|pk)_(test|live)_[0-9a-zA-Z]{24,}', 'Stripe Key'),
        ]
        
        for pattern, key_type in cloud_keys:
            matches = re.findall(pattern, content)
            for match in matches:
                findings.append(ScanResult(
                    url=map_url,
                    type="cloud_keys",
                    severity="High",
                    finding=f"从SourceMap源码中发现{key_type}",
                    detail=f"源文件: {source_file}",
                    source=source_file
                ))
        
        password_patterns = [
            r'password["\s:=]+["\']?([^"\'\s,}]+)',
            r'passwd["\s:=]+["\']?([^"\'\s,}]+)',
            r'(?i)password["\s:=]+["\']?([^\s"\'<]{6,})',
            r'secret["\s:=]+["\']?([^"\'\s,}]+)',
            r'token["\s:=]+["\']?([^"\'\s,}]+)',
            r'api[_-]?key["\s:=]+["\']?([^"\'\s,}]+)',
        ]
        
        for pattern in password_patterns:
            matches = re.findall(pattern, content, re.I)
            for match in matches:
                if len(match) > 3 and not any(x in match.lower() for x in ['null', 'undefined', 'true', 'false', 'example', 'your_']):
                    findings.append(ScanResult(
                        url=map_url,
                        type="hardcoded_creds",
                        severity="High",
                        finding=f"从SourceMap源码中发现硬编码密钥",
                        detail=f"源文件: {source_file}, 内容: {match[:30]}...",
                        source=source_file
                    ))
                    break
        
        return findings
    
    def _extract_api_from_source(self, content: str, source_file: str, map_url: str) -> List[ScanResult]:
        findings = []
        
        api_patterns = [
            r'["\'](/?api[/\w\-]*)["\']',
            r'["\'](/?_next/api[/\w\-]*)["\']',
            r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
            r'axios\.[get|post|put|delete]\s*\(["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        found_apis = set()
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.I)
            for match in matches:
                if match.startswith('http') or match.startswith('/'):
                    found_apis.add(match)
        
        if found_apis:
            findings.append(ScanResult(
                url=map_url,
                type="webpack_api",
                severity="Medium",
                finding=f"从SourceMap发现隐藏API ({len(found_apis)}个)",
                detail=f"源文件: {source_file}, APIs: {'; '.join(list(found_apis)[:5])}",
                source=source_file
            ))
        
        return findings

    def crawl_and_scan(self):
        logger.info(f"{Colors.CYAN}[*] 开始批量扫描，共 {len(self.targets)} 个目标{Colors.END}")
        
        for idx, target in enumerate(self.targets):
            self.current_target_index = idx + 1
            target = target.rstrip('/')
            logger.info(f"{Colors.CYAN}[*] [{self.current_target_index}/{self.total_targets}] 扫描目标: {target}{Colors.END}")
            
            self._scan_single_target(target)
            
            self._save_interim_results()
        
        logger.info(f"{Colors.GREEN}[*] 全部扫描完成!{Colors.END}")
        logger.info(f"{Colors.YELLOW}    结果总数: {len(self.results)}{Colors.END}")
        logger.info(f"{Colors.YELLOW}    端点总数: {len(self.endpoints)}{Colors.END}")
        logger.info(f"{Colors.YELLOW}    子域名: {len(self.subdomains)}{Colors.END}")
        logger.info(f"{Colors.YELLOW}    漏洞发现: {len(self.vuln_findings)}{Colors.END}")
    
    def _update_progress(self, scan_type: str = "page"):
        elapsed = time.time() - self.scan_start_time
        pages = len(self.crawled_pages)
        js_files = len(self.js_files)
        results = len(self.results)
        vuln_findings = len(self.vuln_findings)
        
        if scan_type == "page":
            self.progress_stats['pages_scanned'] = pages
        elif scan_type == "js":
            self.progress_stats['js_analyzed'] = js_files
        
        progress_msg = f"{Colors.CYAN}[进度] 目标:{self.current_target_index}/{self.total_targets} | 页面:{pages} | JS:{js_files} | 发现:{results} | 漏洞:{vuln_findings} | 耗时:{int(elapsed)}s{Colors.END}"
        logger.info(progress_msg)
        
        if self.save_interval > 0 and time.time() - self.last_save_time >= self.save_interval:
            self._save_interim_results()
    
    def _save_interim_results(self):
        if self.save_interval <= 0:
            return
        
        try:
            import json
            import glob
            
            # 使用固定文件名，覆盖之前的临时文件
            interim_file = "flux_interim_latest.json"
            
            interim_data = {
                "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "targets": self.targets,
                "current_target": self.current_target_index,
                "results": [asdict(r) for r in self.results],
                "endpoints": [asdict(e) for e in self.endpoints],
                "subdomains": list(self.subdomains),
                "vuln_findings": [asdict(v) for v in self.vuln_findings],
                "pages_scanned": len(self.crawled_pages),
                "js_files_found": len(self.js_files),
                "fingerprint_results": [
                    {"name": fp.name, "category": fp.category, "confidence": fp.confidence} 
                    for fp in self.fingerprint_results
                ] if hasattr(self, 'fingerprint_results') else []
            }
            
            with open(interim_file, 'w', encoding='utf-8') as f:
                json.dump(interim_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"{Colors.GREEN}[*] 中间结果已保存: {interim_file}{Colors.END}")
            self.last_save_time = time.time()
            
            # 清理旧的临时文件（只保留最新的）
            for old_file in glob.glob("flux_interim*.json"):
                if old_file != interim_file:  # 不删除当前文件
                    try:
                        os.remove(old_file)
                    except:
                        pass
                    
        except Exception as e:
            logger.debug(f"保存中间结果失败: {e}")
    
    def _scan_single_target(self, target_url: str):
        from vuln_test import VULN_TYPE_MAP, TYPE_NAME_MAP
        
        queue = [(target_url, 0)]
        first_page = True
        
        while queue:
            url, depth = queue.pop(0)
            
            if depth > self.depth:
                continue
            
            if url in self.crawled_pages:
                logger.debug(f"页面已爬取: {url}")
                continue
            self.crawled_pages.add(url)
            
            page_progress = len(self.crawled_pages)
            self._update_progress("page")
            
            # 获取页面详细信息
            page_info = self._fetch_page_info(url)
            html_content = page_info['content']
            status_code = page_info['status_code']
            content_length = page_info['content_length']
            title = page_info['title']
            
            # 格式化输出（类似其他工具的格式）
            length_str = f"{content_length}" if content_length > 0 else "未知"
            status_str = f"{status_code}" if status_code > 0 else "未知"
            title_str = title if title else "未知"
            
            logger.info(f"{Colors.BLUE}[*] 长度:[{length_str}] -> 响应:[{status_str}] -> 标题:[{title_str}] -> `{url}`{Colors.END}")
            
            # 只在首页进行指纹识别和API文档解析（不依赖html_content）
            if first_page:
                first_page = False
                logger.info(f"{Colors.CYAN}[*] 开始首页分析 (api_parse={self.api_parse}){Colors.END}")
                
                # 使用page_info中已有的headers和cookies
                headers = page_info.get('headers', {})
                cookies = page_info.get('cookies', {})
                
                # 指纹识别（使用html_content或空字符串）
                fingerprint_content = html_content if html_content else ""
                self.fingerprint_target(url, headers, fingerprint_content, cookies)
                
                # API文档解析
                if html_content:
                    logger.info(f"{Colors.CYAN}[*] 调用 parse_api_documentation{Colors.END}")
                    self.parse_api_documentation(target_url)
            
            if html_content:
                
                jsonp_findings = self.detect_jsonp(html_content, url)
                if jsonp_findings:
                    for f in jsonp_findings:
                        if self.add_result(f):
                            logger.info(f"{Colors.YELLOW}[+] 发现JSONP: {f.finding}{Colors.END}")
                
                cors_finding = self.detect_cors(url)
                if cors_finding:
                    if self.add_result(cors_finding):
                        logger.info(f"{Colors.YELLOW}[+] 发现CORS: {cors_finding.finding}{Colors.END}")
                
                forms = self.extract_forms(html_content, url)
                self.forms.extend(forms)
                
                page_links = self.extract_page_links(html_content, url)
                if page_links:
                    logger.info(f"{Colors.CYAN}[+] 发现 {len(page_links)} 个页面链接{Colors.END}")
                    for link in page_links[:50]:
                        logger.debug(f"    - {link}")
                        link_lower = link.lower()
                        if link_lower.endswith(('.js', '.css', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp', '.woff', '.woff2', '.ttf', '.map', '.json', '.xml')):
                            continue
                        if '/static/' in link_lower and any(x in link_lower for x in ['.js', '.css', '.jpg', '.png', '.gif', '.svg', '.woff']):
                            continue
                        if link not in self.crawled_pages and (link, depth + 1) not in queue:
                            queue.append((link, depth + 1))
                
                subdomains = self.extract_subdomains(html_content)
                if subdomains:
                    logger.info(f"{Colors.GREEN}[+] 发现 {len(subdomains)} 个子域名{Colors.END}")
                    for sub in subdomains[:5]:
                        logger.info(f"    - {sub}")
            else:
                html_content = ""
                # 已经在上面输出了错误信息，这里不需要重复
            
            js_files = self.get_page_js(url)
            logger.info(f"[*] 发现JS文件: {len(js_files)} 个")
            
            for js in js_files:
                if js not in self.js_files:
                    self.js_files.add(js)
                    self.js_files_detail.append({'url': js, 'source': url})
            
            self.pages_detail.append({'url': url, 'status': status_code})
            
            endpoints = self.extract_endpoints(html_content, url)
            for ep in endpoints:
                ep_key = (ep.url, ep.method)
                if ep_key not in self.endpoint_urls:
                    # 验证端点是否真实存在（可选，通过参数控制）
                    if getattr(self, 'verify_endpoints', False):
                        if not self._verify_endpoint_exists(ep, url):
                            logger.debug(f"跳过不存在的端点: {ep.url}")
                            continue
                    
                    self.endpoint_urls.add(ep_key)
                    is_delete = any(x in ep.url.lower() for x in ['delete', 'remove', 'del_', 'drop'])
                    ep.is_delete = is_delete
                    
                    api_type = get_api_type(ep.url)
                    risk_color = {
                        "High": Colors.RED,
                        "Medium": Colors.YELLOW,
                        "Low": Colors.BLUE
                    }.get(ep.risk_level, Colors.WHITE)
                    
                    if is_delete:
                        logger.warning(f"{Colors.RED}[!] 发现DELETE接口: {ep.url} ({api_type}){Colors.END}")
                    elif ep.risk_level == "High":
                        logger.info(f"{risk_color}[+] 发现高风险接口: {ep.url} ({api_type}){Colors.END}")
                    elif ep.risk_level == "Medium":
                        logger.info(f"{risk_color}[+] 发现中风险接口: {ep.url} ({api_type}){Colors.END}")
                    
                    self.endpoints.append(ep)
            
            for js_url in js_files:
                if js_url in self.visited_js:
                    continue
                self.visited_js.add(js_url)
                
                js_progress = len(self.visited_js)
                js_total = len(js_files)
                logger.info(f"{Colors.CYAN}[*] [{js_progress}/{js_total}] 正在分析JS文件...{Colors.END}")
                
                if js_url.startswith('inline:'):
                    parts = js_url.split(':', 3)
                    if len(parts) >= 4:
                        content = parts[3]
                    else:
                        continue
                    js_url_display = url
                else:
                    logger.info(f"{Colors.CYAN}[+] 分析JS: {js_url[:80]}...{Colors.END}")
                    content = self.fetch(js_url)
                    if not content:
                        continue
                    js_url_display = js_url
                
                js_endpoints = self.extract_endpoints(content, js_url_display)
                for ep in js_endpoints:
                    ep_key = (ep.url, ep.method)
                    if ep_key not in self.endpoint_urls:
                        self.endpoint_urls.add(ep_key)
                        is_delete = any(x in ep.url.lower() for x in ['delete', 'remove', 'del_', 'drop'])
                        ep.is_delete = is_delete
                        
                        api_type = get_api_type(ep.url)
                        risk_color = {
                            "High": Colors.RED,
                            "Medium": Colors.YELLOW,
                            "Low": Colors.BLUE
                        }.get(ep.risk_level, Colors.WHITE)
                        
                        if is_delete:
                            logger.warning(f"{Colors.RED}[!] 发现DELETE接口: {ep.url} ({api_type}){Colors.END}")
                        elif ep.risk_level == "High":
                            logger.info(f"{risk_color}[+] 发现高风险接口: {ep.url} ({api_type}){Colors.END}")
                        elif ep.risk_level == "Medium":
                            logger.info(f"{risk_color}[+] 发现中风险接口: {ep.url} ({api_type}){Colors.END}")
                        
                        self.endpoints.append(ep)
                
                logger.debug(f"正在扫描敏感信息: {js_url_display[:50]}...")
                findings = self.scan_sensitive_info(content, js_url_display)
                for f in findings:
                    severity_color = {
                        "Critical": Colors.RED,
                        "High": Colors.ORANGE,
                        "Medium": Colors.YELLOW,
                        "Low": Colors.BLUE
                    }.get(f.severity, Colors.WHITE)
                    type_name = TYPE_NAME_MAP.get(f.type, f.type)
                    if self.add_result(f):
                        logger.info(f"{severity_color}[!] 发现{type_name}: {f.finding}{Colors.END}")
                
                js_subdomains = self.extract_subdomains(content)
                if js_subdomains:
                    for sub in js_subdomains:
                        if sub not in self.subdomains:
                            logger.info(f"{Colors.GREEN}[+] 发现子域名: {sub}{Colors.END}")
                    self.subdomains.update(js_subdomains)
                
                logger.debug(f"正在检测危险组件: {js_url_display[:50]}...")
                vuln_libs = self.detect_vulnerable_libs(content, js_url_display)
                for v in vuln_libs:
                    if self.add_result(v):
                        logger.warning(f"{Colors.RED}[!] 发现危险组件: {v.finding}{Colors.END}")
                
                logger.debug(f"正在分析DOM XSS: {js_url_display[:50]}...")
                dom_xss = self.analyze_dom_xss(content, js_url_display)
                for d in dom_xss:
                    if self.add_result(d):
                        logger.warning(f"{Colors.RED}[!] 发现DOM XSS: {d.finding}{Colors.END}")
                
                logger.debug(f"正在检测SourceMap: {js_url_display[:50]}...")
                sourcemap = self.check_sourcemap(js_url)
                if sourcemap:
                    if self.add_result(sourcemap):
                        logger.warning(f"{Colors.RED}[!] 发现SourceMap泄露: {sourcemap.finding}{Colors.END}")
                
                logger.debug(f"正在分析SourceMap: {js_url_display[:50]}...")
                sm_findings = self.download_and_analyze_sourcemap(js_url, self.session)
                for sm in sm_findings:
                    if self.add_result(sm):
                        logger.warning(f"{Colors.RED}[!] 从SourceMap发现敏感信息: {sm.finding}{Colors.END}")
                
                logger.debug(f"正在检测Webpack: {js_url_display[:50]}...")
                webpack_findings = detect_webpack(content, js_url, self.session)
                for w in webpack_findings:
                    wtype = w.get('type', 'webpack')
                    if wtype == 'Webpack SourceMap':
                        type_name = 'webpack_sourcemap'
                    elif wtype == 'Webpack API':
                        type_name = 'webpack_api'
                        evidence = w.get('evidence', '')
                        if evidence:
                            api_list = [x.strip() for x in evidence.split(';') if x.strip()]
                            for api_path in api_list:
                                if api_path.startswith('/') or api_path.startswith('./') or api_path.startswith('../'):
                                    ep = Endpoint(
                                        url=api_path if api_path.startswith('/') else '/' + api_path.lstrip('./'),
                                        method='GET',
                                        source_js=js_url,
                                        risk_level='Medium',
                                        is_absolute=False,
                                        is_module=False,
                                        is_route=False
                                    )
                                    ep_key = (ep.url, ep.method)
                                    if ep_key not in self.endpoint_urls:
                                        self.endpoint_urls.add(ep_key)
                                        self.endpoints.append(ep)
                                        logger.info(f"{Colors.CYAN}[+] 从Webpack提取API: {ep.url}{Colors.END}")
                    elif wtype == 'Webpack Secrets':
                        type_name = 'webpack_secrets'
                    elif wtype == 'Webpack Endpoints':
                        type_name = 'webpack_endpoints'
                        evidence = w.get('evidence', '')
                        if evidence:
                            endpoint_list = [x.strip() for x in evidence.split(';') if x.strip()]
                            for ep_path in endpoint_list:
                                if ep_path.startswith('/') or ep_path.startswith('./') or ep_path.startswith('../'):
                                    ep = Endpoint(
                                        url=ep_path if ep_path.startswith('/') else '/' + ep_path.lstrip('./'),
                                        method='GET',
                                        source_js=js_url,
                                        risk_level='Low',
                                        is_absolute=False,
                                        is_module=False,
                                        is_route=False
                                    )
                                    ep_key = (ep.url, ep.method)
                                    if ep_key not in self.endpoint_urls:
                                        self.endpoint_urls.add(ep_key)
                                        self.endpoints.append(ep)
                                        logger.info(f"{Colors.CYAN}[+] 从Webpack提取端点: {ep.url}{Colors.END}")
                    else:
                        type_name = 'webpack'
                    
                    if self.add_result(ScanResult(
                        url=w.get('url', js_url),
                        type=type_name,
                        severity=w.get('severity', 'Medium'),
                        finding=w.get('detail', 'Webpack信息泄露'),
                        detail=w.get('evidence', ''),
                        source=js_url
                    )):
                        logger.warning(f"{Colors.YELLOW}[!] 发现{type_name}: {w.get('detail')}{Colors.END}")
        
        if self.fuzz_paths:
            logger.info(f"{Colors.CYAN}[*] 开始路径fuzzing...{Colors.END}")
            fuzz_results = self.fuzz_sensitive_paths(target_url)
            for f in fuzz_results:
                if self.add_result(f):
                    logger.info(f"{Colors.GREEN}[+] 发现敏感路径: {f.finding}{Colors.END}")
        
        if self.vuln_test:
            logger.info(f"{Colors.CYAN}[*] 开始漏洞测试...{Colors.END}")
            
            logger.info(f"{Colors.CYAN}[*] 提取到的API端点数量: {len(self.endpoints)}{Colors.END}")
            logger.info(f"{Colors.CYAN}[*] 提取到的表单数量: {len(self.forms)}{Colors.END}")
            logger.info(f"{Colors.CYAN}[*] 提取到的页面链接: {len(self.crawled_pages)}{Colors.END}")
            
            self.test_endpoints_vulns()
            
            logger.info(f"{Colors.CYAN}[*] 检测SSRF参数...{Colors.END}")
            ssrf_findings = self.detect_ssrf_params()
            if ssrf_findings:
                logger.warning(f"{Colors.RED}[!] 发现 {len(ssrf_findings)} 个SSRF潜在参数{Colors.END}")
            for s in ssrf_findings:
                if self.add_result(s):
                    logger.warning(f"{Colors.RED}[!] {s.detail} - 参数: {s.finding}{Colors.END}")
        
        logger.info(f"{Colors.GREEN}[*] {target_url} 扫描完成!{Colors.END}")

    def generate_html_report(self, output_file: str = None):
        if not self.results and not self.endpoints and not self.subdomains and not self.vuln_findings:
            logger.warning("未发现任何扫描结果")
            return
        
        scan_stats = {
            'pages': len(self.crawled_pages),
            'forms': len(self.forms),
            'js_files': len(self.visited_js),
            'absolute_apis': len([e for e in self.endpoints if getattr(e, 'is_absolute', False)]),
            'relative_apis': len([e for e in self.endpoints if not getattr(e, 'is_absolute', True)]),
            'module_paths': len([e for e in self.endpoints if getattr(e, 'is_module', False)]),
            'frontend_routes': len([e for e in self.endpoints if getattr(e, 'is_route', False)]),
        }
        
        html_content = generate_html_report(
            targets=self.targets,
            results=self.results,
            endpoints=self.endpoints,
            subdomains=list(self.subdomains) if self.subdomains else [],
            vuln_findings=self.vuln_findings if self.vuln_findings else [],
            output_file=output_file,
            scan_stats=scan_stats,
            js_files_list=self.js_files_detail,
            pages_list=self.pages_detail,
            fingerprint_results=self.fingerprint_results if self.fingerprint_results else [],
            api_docs=self.parsed_api_docs if self.parsed_api_docs else []
        )
        
        if output_file:
            if not output_file.endswith('.html'):
                output_file += '.html'
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"{Colors.GREEN}[*] HTML报告已保存: {output_file}{Colors.END}")
        else:
            filename = f"jsscan_report_{int(time.time())}.html"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"{Colors.GREEN}[*] HTML报告已保存: {filename}{Colors.END}")

    def _generate_html(self, severity_stats, endpoints_by_method, results_by_type) -> str:
        target_escaped = html.escape(self.target_url)
        
        findings_table = ""
        for i, r in enumerate(self.results, 1):
            severity_class = r.severity.lower()
            type_escaped = html.escape(r.type)
            finding_escaped = html.escape(r.finding)
            detail_escaped = html.escape(r.detail[:80])
            source_escaped = html.escape(r.source[:60])
            
            findings_table += f"""
            <tr>
                <td>{i}</td>
                <td><span class="severity {severity_class}">{r.severity}</span></td>
                <td>{finding_escaped}</td>
                <td class="detail-cell">{detail_escaped}</td>
                <td class="source-cell" title="{source_escaped}">{source_escaped}</td>
            </tr>
            """
        
        endpoints_table = ""
        for ep in self.endpoints[:50]:
            risk_class = ep.risk_level.lower()
            method_class = ep.method.lower()
            url_escaped = html.escape(ep.url[:70])
            source_escaped = html.escape(ep.source_js[:40])
            
            endpoints_table += f"""
            <tr>
                <td><span class="method {method_class}">{ep.method}</span></td>
                <td class="url-cell" title="{html.escape(ep.url)}">{url_escaped}</td>
                <td><span class="risk {risk_class}">{ep.risk_level}</span></td>
                <td class="source-cell" title="{source_escaped}">{source_escaped}</td>
            </tr>
            """
        
        type_stats_html = ""
        for type_name, findings in sorted(results_by_type.items(), key=lambda x: len(x[1]), reverse=True):
            type_stats_html += f"""
            <div class="type-stat">
                <span class="type-name">{html.escape(type_name)}</span>
                <span class="type-count">{len(findings)}</span>
            </div>
            """
        
        return f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JS-Scan-Pro 安全扫描报告</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {{
            --primary-color: #4F46E5;
            --bg-dark: #0F172A;
            --bg-card: #1E293B;
            --text-primary: #F1F5F9;
            --text-secondary: #94A3B8;
            --critical: #EF4444;
            --high: #F97316;
            --medium: #EAB308;
            --low: #22C55E;
        }}
        
        body {{
            background: linear-gradient(135deg, var(--bg-dark) 0%, #1a1a2e 100%);
            min-height: 100vh;
            color: var(--text-primary);
            font-family: 'Segoe UI', system-ui, sans-serif;
        }}
        
        .header {{
            background: linear-gradient(90deg, var(--primary-color), #7C3AED);
            padding: 2rem 0;
            margin-bottom: 2rem;
            box-shadow: 0 4px 20px rgba(79, 70, 229, 0.3);
        }}
        
        .header h1 {{
            margin: 0;
            font-weight: 700;
            letter-spacing: -0.5px;
        }}
        
        .target-url {{
            background: rgba(255,255,255,0.1);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-family: monospace;
            word-break: break-all;
        }}
        
        .stat-card {{
            background: var(--bg-card);
            border-radius: 16px;
            padding: 1.5rem;
            text-align: center;
            transition: transform 0.3s, box-shadow 0.3s;
            border: 1px solid rgba(255,255,255,0.05);
        }}
        
        .stat-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        }}
        
        .stat-number {{
            font-size: 3rem;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 0.5rem;
        }}
        
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .critical .stat-number {{ color: var(--critical); }}
        .high .stat-number {{ color: var(--high); }}
        .medium .stat-number {{ color: var(--medium); }}
        .low .stat-number {{ color: var(--low); }}
        
        .section-card {{
            background: var(--bg-card);
            border-radius: 16px;
            overflow: hidden;
            margin-bottom: 1.5rem;
            border: 1px solid rgba(255,255,255,0.05);
        }}
        
        .section-header {{
            background: rgba(0,0,0,0.2);
            padding: 1rem 1.5rem;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        
        .section-title {{
            font-size: 1.25rem;
            font-weight: 600;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .table {{
            margin: 0;
            color: var(--text-primary);
        }}
        
        .table thead th {{
            background: rgba(0,0,0,0.3);
            border: none;
            padding: 1rem;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 1px;
            color: var(--text-secondary);
        }}
        
        .table tbody td {{
            padding: 1rem;
            border-color: rgba(255,255,255,0.05);
            vertical-align: middle;
        }}
        
        .table tbody tr:hover {{
            background: rgba(79, 70, 229, 0.1);
        }}
        
        .severity {{
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .severity.critical {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); }}
        .severity.high {{ background: rgba(249, 115, 22, 0.2); color: var(--high); }}
        .severity.medium {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); }}
        .severity.low {{ background: rgba(34, 197, 94, 0.2); color: var(--low); }}
        
        .method {{
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        
        .method.get {{ background: #22C55E; color: #000; }}
        .method.post {{ background: #3B82F6; color: #fff; }}
        .method.put {{ background: #F59E0B; color: #000; }}
        .method.delete {{ background: #EF4444; color: #fff; }}
        
        .risk {{
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.7rem;
            font-weight: 600;
        }}
        
        .risk.high {{ background: rgba(239, 68, 68, 0.2); color: var(--critical); }}
        .risk.medium {{ background: rgba(234, 179, 8, 0.2); color: var(--medium); }}
        .risk.low {{ background: rgba(34, 197, 94, 0.2); color: var(--low); }}
        
        .detail-cell, .url-cell, .source-cell {{
            max-width: 250px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-family: monospace;
            font-size: 0.85rem;
        }}
        
        .table-wrapper {{
            overflow-x: auto;
            -webkit-overflow-scrolling: touch;
        }}
        
        .table-wrapper table {{
            min-width: 800px;
        }}
        
        .type-stat {{
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: rgba(255,255,255,0.05);
            padding: 0.5rem 1rem;
            border-radius: 8px;
            margin: 0.25rem;
        }}
        
        .type-name {{
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}
        
        .type-count {{
            background: var(--primary-color);
            padding: 0.125rem 0.5rem;
            border-radius: 10px;
            font-size: 0.75rem;
            font-weight: 600;
        }}
        
        .method-stats {{
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }}
        
        .method-stat {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
        }}
        
        .max-height-500 {{
            max-height: 500px;
            overflow-y: auto;
        }}
        
        ::-webkit-scrollbar {{
            width: 8px;
            height: 8px;
        }}
        
        ::-webkit-scrollbar-track {{
            background: rgba(0,0,0,0.2);
        }}
        
        ::-webkit-scrollbar-thumb {{
            background: var(--primary-color);
            border-radius: 4px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-md-8">
                    <h1><i class="bi bi-shield-check"></i> JS-Scan-Pro 安全扫描报告</h1>
                    <p class="mb-0 mt-2" style="opacity: 0.8;">JavaScript 安全漏洞分析 · 敏感信息检测</p>
                </div>
                <div class="col-md-4 text-md-end">
                    <div class="target-url">{target_escaped}</div>
                    <p class="mb-0 mt-2" style="opacity: 0.6;"><i class="bi bi-clock"></i> {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
                </div>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="row g-4 mb-4">
            <div class="col-md-3">
                <div class="stat-card critical">
                    <div class="stat-number">{severity_stats["critical"]}</div>
                    <div class="stat-label"><i class="bi bi-exclamation-triangle"></i> 严重</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card high">
                    <div class="stat-number">{severity_stats["high"]}</div>
                    <div class="stat-label"><i class="bi bi-exclamation-circle"></i> 高危</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card medium">
                    <div class="stat-number">{severity_stats["medium"]}</div>
                    <div class="stat-label"><i class="bi bi-info-circle"></i> 中危</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="stat-card low">
                    <div class="stat-number">{severity_stats["low"]}</div>
                    <div class="stat-label"><i class="bi bi-check-circle"></i> 低危</div>
                </div>
            </div>
        </div>
        
        <div class="row g-4 mb-4">
            <div class="col-md-6">
                <div class="section-card">
                    <div class="section-header">
                        <h5 class="section-title"><i class="bi bi-pie-chart"></i> 风险类型分布</h5>
                    </div>
                    <div class="p-3">
                        {type_stats_html}
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="section-card">
                    <div class="section-header">
                        <h5 class="section-title"><i class="bi bi-link-45deg"></i> API端点统计</h5>
                    </div>
                    <div class="p-3">
                        <div class="method-stats">
                            <div class="method-stat">
                                <span class="method get">GET</span>
                                <span>{endpoints_by_method.get("GET", 0)}</span>
                            </div>
                            <div class="method-stat">
                                <span class="method post">POST</span>
                                <span>{endpoints_by_method.get("POST", 0)}</span>
                            </div>
                            <div class="method-stat">
                                <span class="method put">PUT</span>
                                <span>{endpoints_by_method.get("PUT", 0)}</span>
                            </div>
                            <div class="method-stat">
                                <span class="method delete">DELETE</span>
                                <span>{endpoints_by_method.get("DELETE", 0)}</span>
                            </div>
                            <div class="method-stat">
                                <span>其他: {endpoints_by_method.get("OTHER", 0)}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="section-card mb-4">
            <div class="section-header">
                <h5 class="section-title"><i class="bi bi-exclamation-diamond-fill"></i> 安全发现 ({len(self.results)})</h5>
            </div>
            <div class="table-wrapper max-height-500">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th style="width: 50px;">#</th>
                            <th style="width: 80px;">等级</th>
                            <th>发现项</th>
                            <th>详情</th>
                            <th>来源</th>
                        </tr>
                    </thead>
                    <tbody>
                        {findings_table}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="section-card mb-4">
            <div class="section-header">
                <h5 class="section-title"><i class="bi bi-link"></i> API端点列表 ({len(self.endpoints)})</h5>
            </div>
            <div class="table-wrapper max-height-500">
                <table class="table table-dark table-hover">
                    <thead>
                        <tr>
                            <th style="width: 80px;">方法</th>
                            <th>URL</th>
                            <th style="width: 80px;">风险</th>
                            <th>来源JS</th>
                        </tr>
                    </thead>
                    <tbody>
                        {endpoints_table}
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="footer">
            <p><i class="bi bi-code-slash"></i> Generated by FLUX v3.0.5</p>
        </div>
    </div>
</body>
</html>'''

def parse_args():
    parser = argparse.ArgumentParser(
        description='FLUX v3.0.5: 专业的Web安全扫描工具 (25,000+指纹库 | 40+WAF检测 | 差分测试 | SwaggerHound | 误报过滤)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
===================================================================
                        快速开始
===================================================================

【推荐】一键全功能扫描 (自动启用除delete外所有检测):
  python flux.py https://example.com --full --dnslog xxx.dnslog.cn -o report.html

  一键扫描将自动启用:
  [OK] 指纹识别 (25,000+规则, 多特征验证)
  [OK] API文档解析 (Swagger/OpenAPI/Postman)
  [OK] SwaggerHound API自动测试
  [OK] 密钥有效性验证
  [OK] 敏感路径Fuzzing
  [OK] 参数Fuzzing (从JS提取API参数)
  [OK] 漏洞主动测试 (SQLi/XSS/LFI/RCE/SSTI/SSRF, 带差分检测和误报过滤)
  [OK] WAF检测与绕过 (40+种WAF含国产厂商)
  [OK] 智能速率限制 (自适应请求频率)
  [OK] 流量指纹伪装 (Header轮换)

===================================================================
                        常用示例
===================================================================

  # 单目标快速扫描 (新参数方式)
  python flux.py -t https://example.com

  # 批量扫描(文件)
  python flux.py -tf urls.txt

  # 深度扫描 (爬取深度5)
  python flux.py -t https://example.com -d 5

  # URL包含特殊字符(&或=) - Windows CMD必须用双引号
  python flux.py -t "https://example.com/path?a=1&b=2" --full -o report.html

  # URL包含特殊字符 - 其他系统可用单引号
  python flux.py -t 'https://example.com/path?a=1&b=2' --full -o report.html

  # 漏洞主动测试 (带差分检测, 误报率降低80%+)
  python flux.py -t https://example.com --vuln-test

  # 仅进行指纹识别
  python flux.py -t https://example.com --fingerprint

  # 仅进行API文档解析
  python flux.py -t https://example.com --api-only

  # 仅检测敏感信息/密钥
  python flux.py -t https://example.com --keys-only

  # 仅进行敏感路径扫描
  python flux.py -t https://example.com --paths-only

  # 敏感路径fuzzing
  python flux.py -t https://example.com --fuzz-paths

  # 生成HTML报告
  python flux.py -t https://example.com -o report.html

  # 标准扫描 (推荐, 平衡速度与深度)
  python flux.py https://example.com --vuln-test -o report.html

  # 全面扫描 (深度, 包含DELETE测试)
  python flux.py https://example.com --vuln-test --fuzz --fuzz-paths --verify-keys --test-delete -d 5 -o report.html

  # 使用代理扫描 (通过Burp等)
  python flux.py https://example.com --vuln-test --proxy http://127.0.0.1:8080 -o report.html

===================================================================
                        功能特性
===================================================================

  [OK] API端点提取 (绝对路径/相对路径/模块路径, 支持JS字符串拼接)
  [OK] 敏感信息检测 (云密钥/Token/个人信息等, 含熵值验证过滤假阳性)
  [OK] 漏洞主动测试 (SQLi/XSS/LFI/RCE/SSTI/SSRF/XXE等, 带差分检测)
  [OK] 指纹识别 (25,000+规则, 多特征交叉验证, 置信度评分)
  [OK] WAF检测与绕过 (40+种WAF含24种国产厂商, 多种绕过技术)
  [OK] CSRF Token自动提取 (支持6种常见Token格式)
  [OK] Cookie持久化 (保存/加载会话状态, 支持登录后扫描)
  [OK] 智能速率限制 (自适应调整请求频率, 避免被封IP)
  [OK] 流量指纹伪装 (4种真实浏览器Header轮换)
  [OK] JS代码混淆还原 (eval/atob/String.fromCharCode/十六进制/Unicode解码)
  [OK] API文档解析 (Swagger/OpenAPI/Postman自动发现)
  [OK] API参数Fuzzing (从JS提取参数名并自动测试)
  [OK] 云安全测试 (Bucket遍历/密钥泄露检测)
  [OK] 子域名提取
  [OK] 美观HTML报告 (含统计图表)

===================================================================
        """
    )
    parser.add_argument('-t', '--target', type=str, help='单个目标URL (使用-tf指定目标文件)')
    parser.add_argument('-tf', '--target-file', type=str, help='从文件加载目标列表 (每行一个URL)')
    parser.add_argument('-tc', '--threads', type=int, default=20, help='并发线程数 (默认: 20)')
    parser.add_argument('--timeout', type=int, default=15, help='超时时间 (默认: 15秒)')
    parser.add_argument('--proxy', type=str, help='代理服务器')
    parser.add_argument('-o', '--output', type=str, help='输出文件 (支持.html/.json)')
    
    parser.add_argument('--full', action='store_true', help='一键全功能扫描 (启用:指纹识别/API解析/密钥验证/路径Fuzz/参数Fuzz/漏洞测试/WAF绕过/DOM XSS/智能限速/流量伪装)')
    parser.add_argument('--fingerprint', action='store_true', help='仅进行指纹识别')
    parser.add_argument('-d', '--depth', type=int, default=3, help='爬取深度 (默认: 3)')
    parser.add_argument('--save-interval', type=int, default=30, help='结果保存间隔(秒), 0为仅结束时保存 (默认: 30)')
    parser.add_argument('--verify-keys', action='store_true', help='验证密钥有效性')
    parser.add_argument('--fuzz', action='store_true', help='启用参数fuzzing')
    parser.add_argument('--fuzz-paths', action='store_true', help='启用敏感路径fuzzing')
    parser.add_argument('--vuln-test', action='store_true', help='启用漏洞主动测试 (SQLi/XSS/LFI/RCE/SSRF/RCE增强)')
    parser.add_argument('--test-delete', action='store_true', help='测试DELETE类危险接口')
    parser.add_argument('--dnslog', type=str, help='指定DNSLog域名用于盲SSRF测试 (例如: xxx.dnslog.cn)')
    parser.add_argument('--api-parse', action='store_true', help='启用API文档解析 (Swagger/OpenAPI)')
    parser.add_argument('--verify-endpoints', action='store_true', help='验证提取的端点是否真实存在（减少误报）')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    parser.add_argument('-q', '--quiet', action='store_true', help='安静模式')
    
    return parser.parse_args()


def main():
    args = parse_args()
    
    # 支持从环境变量读取URL（解决URL中特殊字符导致CMD解析问题）
    import os
    if os.environ.get('FLUX_TARGET'):
        args.target = os.environ.get('FLUX_TARGET')
        logger.info(f"[*] 从环境变量读取目标: {args.target}")

    # Banner显示逻辑
    try:
        import platform
        if platform.system() == 'Windows':
            BANNER = r"""
================================================================

  ███████╗██╗     ██╗   ██╗██╗  ██╗
  ██╔════╝██║     ██║   ██║╚██╗██╔╝
  █████╗  ██║     ██║   ██║ ╚███╔╝ 
  ██╔══╝  ██║     ██║   ██║ ██╔██╗ 
  ██║     ███████╗╚██████╔╝██╔╝ ██╗
  ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝

         专业的Web安全扫描工具 FLUX v3.0.5
              Author: ROOT4044

================================================================
"""
        else:
            BANNER = r"""
\033[96m================================================================

  \033[93m███████╗██╗     ██╗   ██╗██╗  ██╗\033[96m
  \033[93m██╔════╝██║     ██║   ██║╚██╗██╔╝\033[96m
  \033[93m█████╗  ██║     ██║   ██║ ╚███╔╝ \033[96m
  \033[93m██╔══╝  ██║     ██║   ██║ ██╔██╗ \033[96m
  \033[93m██║     ███████╗╚██████╔╝██╔╝ ██╗\033[96m
  \033[93m╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝\033[96m

         专业的Web安全扫描工具 \033[93mFLUX v3.0.5\033[96m
              Author: ROOT4044

================================================================\033[0m
"""
    except:
        BANNER = r"""
================================================================

  ███████╗██╗     ██╗   ██╗██╗  ██╗
  ██╔════╝██║     ██║   ██║╚██╗██╔╝
  █████╗  ██║     ██║   ██║ ╚███╔╝ 
  ██╔══╝  ██║     ██║   ██║ ██╔██╗ 
  ██║     ███████╗╚██████╔╝██╔╝ ██╗
  ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝

         专业的Web安全扫描工具 FLUX v3.0.5
              Author: ROOT4044

================================================================
"""
    print(BANNER)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    # 如果启用--full，自动开启所有功能
    if args.full:
        logger.info("[*] 启用一键全功能扫描模式")
        args.verify_keys = True
        args.fuzz = True
        args.fuzz_paths = True
        args.vuln_test = True
        # args.test_delete = True  # --full不包含DELETE测试，需要单独添加--test-delete
        args.api_parse = True
        logger.info("[*] 已启用: 密钥验证 | 参数Fuzzing | 路径Fuzzing | 漏洞测试 | API解析")
        logger.info("[*] 提示: 如需DELETE测试，请额外添加 --test-delete 参数")
    
    # DNSLog配置 - 用于盲SSRF测试
    if args.vuln_test or args.full:
        from vuln_test_enhanced import set_dnslog_domain, get_dnslog_domain
        
        if args.dnslog:
            # 使用命令行指定的DNSLog域名
            set_dnslog_domain(args.dnslog)
            logger.info(f"[*] DNSLog域名已设置: {args.dnslog}")
        elif args.full:
            # --full模式下，如果没有指定--dnslog，自动跳过DNSLog配置
            logger.info("[*] 未指定--dnslog参数，将跳过盲SSRF测试")
        else:
            # 交互式询问用户（仅在--vuln-test模式下）
            print("\n" + "="*60)
            print("  SSRF漏洞测试 - DNSLog配置")
            print("="*60)
            print("  提示: 盲SSRF测试需要DNSLog服务来验证")
            print("  请访问 https://dnslog.cn 获取一个子域名")
            print("  或直接按回车跳过盲SSRF测试")
            print("="*60)
            
            try:
                dnslog_input = input("\n请输入DNSLog子域名 (例如: xxx.dnslog.cn): ").strip()
                if dnslog_input:
                    set_dnslog_domain(dnslog_input)
                    logger.info(f"[*] DNSLog域名已配置: {dnslog_input}")
                else:
                    logger.info("[!] 未配置DNSLog，将跳过盲SSRF测试")
            except KeyboardInterrupt:
                print("\n[!] 用户取消输入，跳过盲SSRF测试")
            except Exception as e:
                logger.debug(f"DNSLog输入错误: {e}")
    
    # 处理目标参数 (-tf 参数优先)
    target_input = ""
    if args.target_file:
        if os.path.isfile(args.target_file):
            with open(args.target_file, 'r', encoding='utf-8') as f:
                targets = [line.strip() for line in f if line.strip()]
            target_input = ','.join(targets)
            logger.info(f"[*] 从文件 {args.target_file} 加载了 {len(targets)} 个目标")
        else:
            logger.error(f"[!] 目标列表文件不存在: {args.target_file}")
            return
    elif args.target:
        target_input = args.target
    else:
        logger.error("[!] 请使用 -t 指定目标URL 或 -tf 指定目标文件")
        return
    
    # 处理单功能扫描模式
    if args.fingerprint:
        logger.info("[*] 模式: 仅进行指纹识别")
        args.api_parse = False
        args.verify_keys = False
        args.fuzz = False
        args.fuzz_paths = False
        args.vuln_test = False
        args.test_delete = False
    
    scanner = FLUX(
        target=target_input,
        depth=args.depth,
        timeout=args.timeout,
        proxy=args.proxy,
        threads=args.threads,
        verify_keys=args.verify_keys,
        fuzz_params=args.fuzz,
        vuln_test=args.vuln_test,
        fuzz_paths=args.fuzz_paths,
        test_delete=args.test_delete,
        api_parse=args.api_parse,
        verify_endpoints=args.verify_endpoints,
        save_interval=args.save_interval
    )
    
    try:
        scanner.crawl_and_scan()
        
        if args.output:
            if args.output.endswith('.json'):
                import json
                report_data = {
                    "targets": scanner.targets,
                    "scan_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "results": [asdict(r) for r in scanner.results],
                    "endpoints": [asdict(e) for e in scanner.endpoints],
                    "subdomains": list(scanner.subdomains),
                    "vuln_findings": [asdict(v) for v in scanner.vuln_findings],
                }
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(report_data, f, ensure_ascii=False, indent=2)
                print(f"JSON报告已保存: {args.output}")
            else:
                scanner.generate_html_report(args.output)
        else:
            scanner.generate_html_report()
        
        print(f"\n{Colors.CYAN}{'='*60}{Colors.END}")
        print(f"{Colors.CYAN}扫描摘要:{Colors.END}")
        print(f"  目标: {len(scanner.targets)}")
        print(f"  敏感信息: {len(scanner.results)}")
        print(f"  API端点: {len(scanner.endpoints)} (DELETE接口: {sum(1 for e in scanner.endpoints if e.is_delete)})")
        print(f"  子域名: {len(scanner.subdomains)}")
        print(f"  漏洞发现: {len(scanner.vuln_findings)}")
        print(f"{Colors.CYAN}{'='*60}{Colors.END}")
        
    except KeyboardInterrupt:
        logger.warning("扫描被用户中断")
        if scanner.results or scanner.endpoints or scanner.vuln_findings:
            print(f"\n{Colors.YELLOW}已发现扫描结果:{Colors.END}")
            print(f"  敏感信息: {len(scanner.results)}")
            print(f"  API端点: {len(scanner.endpoints)}")
            print(f"  漏洞发现: {len(scanner.vuln_findings)}")
            print(f"\n{Colors.CYAN}是否保存当前扫描结果? (y/n): {Colors.END}", end="")
            try:
                choice = input().strip().lower()
                if choice == 'y' or choice == 'Y' or choice == '是':
                    scanner.generate_html_report()
                    print(f"{Colors.GREEN}结果已保存!{Colors.END}")
                else:
                    print(f"{Colors.YELLOW}已放弃保存{Colors.END}")
            except:
                pass
    except Exception as e:
        logger.error(f"扫描出错: {e}")
        raise

if __name__ == '__main__':
    main()
