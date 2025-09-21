"""
日志标准化模块
将不同源的日志标准化为统一的事件结构，并进行安全解码和去混淆
"""

import re
import html
import base64
import urllib.parse
import binascii
from typing import Dict, Any, List, Optional, Set
import logging
from datetime import datetime, timezone
import uuid

from .config import get_config

logger = logging.getLogger(__name__)

class LogNormalizer:
    """日志标准化器"""
    
    def __init__(self):
        self.config = get_config()
        self.max_decode_rounds = self.config.get("system.max_decode_rounds", 5)
        
        # 编译解码模式
        self._compile_decode_patterns()
        
        # 敏感字段列表
        self.sensitive_fields = set([
            'password', 'passwd', 'pwd', 'secret', 'key', 'token', 
            'authorization', 'auth', 'credential', 'api_key',
            'access_token', 'refresh_token', 'session_id'
        ])
        
    def _compile_decode_patterns(self):
        """编译解码正则表达式"""
        # URL编码
        self.url_encoded_pattern = re.compile(r'%[0-9A-Fa-f]{2}')
        
        # 十六进制编码
        self.hex_pattern = re.compile(r'\\x[0-9A-Fa-f]{2}')
        
        # Unicode编码
        self.unicode_pattern = re.compile(r'\\u[0-9A-Fa-f]{4}')
        
        # Base64模式
        self.base64_pattern = re.compile(r'[A-Za-z0-9+/]{4,}={0,2}')
        
        # SQL注释模式
        self.sql_comment_patterns = [
            re.compile(r'/\*.*?\*/', re.DOTALL),  # /* 注释 */
            re.compile(r'--.*$', re.MULTILINE),   # -- 注释
            re.compile(r'#.*$', re.MULTILINE),    # # 注释
        ]
        
        # 空白字符标准化
        self.whitespace_pattern = re.compile(r'\s+')
        
    def normalize(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """标准化日志事件"""
        try:
            # 创建标准化事件结构
            normalized = self._create_standard_event(event)
            
            # 提取和标准化字段
            self._extract_standard_fields(normalized, event)
            
            # 安全解码
            self._decode_fields(normalized)
            
            # 脱敏处理
            self._mask_sensitive_data(normalized)
            
            # 生成事件ID
            normalized['event_id'] = str(uuid.uuid4())
            
            return normalized
            
        except Exception as e:
            logger.error(f"标准化事件失败: {e}")
            return self._create_error_event(event, str(e))
            
    def _create_standard_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """创建标准事件结构"""
        return {
            'event_id': '',
            'timestamp': event.get('timestamp', datetime.now(timezone.utc)),
            'tenant': event.get('tenant', 'default'),
            'log_type': event.get('log_type', 'unknown'),
            'severity': 'info',
            'src_ip': None,
            'user': None,
            'user_agent': None,
            'method': None,
            'path': None,
            'query_string': None,
            'status_code': None,
            'message': '',
            'raw_message': event.get('raw_message', ''),
            'decoded_fields': {},
            'masked_fields': [],
            'metadata': {
                'source_file': event.get('source_file'),
                'line_number': event.get('line_number'),
                'parsed_data': event.get('parsed_data', {})
            }
        }
        
    def _extract_standard_fields(self, normalized: Dict[str, Any], event: Dict[str, Any]) -> None:
        """提取标准字段"""
        # 直接映射的字段
        direct_fields = [
            'src_ip', 'user', 'user_agent', 'method', 'path', 
            'query_string', 'status_code', 'message'
        ]
        
        for field in direct_fields:
            if field in event and event[field] is not None:
                normalized[field] = event[field]
                
        # 特殊处理
        if 'request' in event:
            normalized['message'] = event['request']
            
        if not normalized['message'] and 'raw_message' in event:
            normalized['message'] = event['raw_message']
            
        # 提取查询参数
        if 'query_params' in event:
            normalized['metadata']['query_params'] = event['query_params']
            
        # 提取SQL相关信息
        if event.get('log_type') == 'database':
            normalized['metadata']['sql_statement'] = event.get('sql_statement')
            normalized['metadata']['sql_type'] = event.get('sql_type')
            
        # 提取容器信息
        if event.get('log_type') in ['kubernetes', 'container']:
            normalized['metadata']['pod_name'] = event.get('pod_name')
            normalized['metadata']['container_name'] = event.get('container_name')
            
        # 提取云审计信息
        if event.get('log_type') == 'cloud_audit':
            normalized['metadata']['resource'] = event.get('resource')
            normalized['metadata']['action'] = event.get('action')
            
    def _decode_fields(self, event: Dict[str, Any]) -> None:
        """安全解码字段"""
        fields_to_decode = ['path', 'query_string', 'message', 'user_agent']
        
        for field in fields_to_decode:
            if field in event and event[field]:
                original = str(event[field])
                decoded = self._safe_decode(original)
                
                if decoded != original:
                    event['decoded_fields'][field] = decoded
                    # 更新原字段为解码后的值
                    event[field] = decoded
                    
        # 解码查询参数
        if 'metadata' in event and 'query_params' in event['metadata']:
            decoded_params = {}
            for key, value in event['metadata']['query_params'].items():
                decoded_key = self._safe_decode(str(key))
                decoded_value = self._safe_decode(str(value))
                decoded_params[decoded_key] = decoded_value
                
            event['metadata']['decoded_query_params'] = decoded_params
            
    def _safe_decode(self, text: str) -> str:
        """安全多轮解码"""
        if not text:
            return text
            
        current = text
        rounds = 0
        
        while rounds < self.max_decode_rounds:
            rounds += 1
            previous = current
            
            # URL解码
            try:
                if self.url_encoded_pattern.search(current):
                    current = urllib.parse.unquote(current)
            except Exception:
                pass
                
            # HTML解码
            try:
                if '&' in current and ';' in current:
                    decoded = html.unescape(current)
                    if decoded != current:
                        current = decoded
            except Exception:
                pass
                
            # 十六进制解码
            try:
                if self.hex_pattern.search(current):
                    current = re.sub(
                        r'\\x([0-9A-Fa-f]{2})',
                        lambda m: chr(int(m.group(1), 16)),
                        current
                    )
            except Exception:
                pass
                
            # Unicode解码
            try:
                if self.unicode_pattern.search(current):
                    current = current.encode().decode('unicode_escape')
            except Exception:
                pass
                
            # Base64解码（谨慎处理）
            try:
                if len(current) > 4 and self.base64_pattern.fullmatch(current):
                    decoded = base64.b64decode(current).decode('utf-8', errors='ignore')
                    if decoded and decoded.isprintable():
                        current = decoded
            except Exception:
                pass
                
            # 如果没有变化，停止解码
            if current == previous:
                break
                
        # 标准化空白字符
        current = self.whitespace_pattern.sub(' ', current).strip()
        
        # 去除SQL注释
        current = self._remove_sql_comments(current)
        
        return current
        
    def _remove_sql_comments(self, text: str) -> str:
        """去除SQL注释"""
        result = text
        
        for pattern in self.sql_comment_patterns:
            result = pattern.sub(' ', result)
            
        # 标准化空白
        result = self.whitespace_pattern.sub(' ', result).strip()
        
        return result
        
    def _mask_sensitive_data(self, event: Dict[str, Any]) -> None:
        """脱敏敏感数据"""
        masking_config = self.config.get("masking", {})
        if not masking_config.get("enabled", True):
            return
            
        patterns = masking_config.get("patterns", {})
        
        # 脱敏模式
        mask_patterns = {
            'email': (
                re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
                patterns.get('email', '***@***.***')
            ),
            'phone': (
                re.compile(r'(\+?86)?1[3-9]\d{9}'),
                patterns.get('phone', '***-****-****')
            ),
            'id_card': (
                re.compile(r'\b[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]\b'),
                patterns.get('id_card', '****-**-**-****')
            ),
            'credit_card': (
                re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'),
                patterns.get('credit_card', '****-****-****-****')
            ),
            'jwt': (
                re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
                '***JWT_TOKEN***'
            ),
            'api_key': (
                re.compile(r'(?i)(api[_-]?key|access[_-]?key|secret[_-]?key)\s*[:=]\s*[\'"]?([a-zA-Z0-9]{20,})[\'"]?'),
                lambda m: f"{m.group(1)}=***MASKED***"
            )
        }
        
        # 需要脱敏的字段
        fields_to_mask = ['message', 'path', 'query_string', 'user_agent', 'raw_message']
        
        for field in fields_to_mask:
            if field in event and event[field]:
                original = str(event[field])
                masked = original
                
                for mask_type, (pattern, replacement) in mask_patterns.items():
                    if pattern.search(masked):
                        if callable(replacement):
                            masked = pattern.sub(replacement, masked)
                        else:
                            masked = pattern.sub(replacement, masked)
                        
                        if mask_type not in event['masked_fields']:
                            event['masked_fields'].append(mask_type)
                            
                if masked != original:
                    event[field] = masked
                    
        # 脱敏查询参数
        if 'metadata' in event and 'query_params' in event['metadata']:
            params = event['metadata']['query_params']
            masked_params = {}
            
            for key, value in params.items():
                # 检查键名是否敏感
                if any(sensitive in key.lower() for sensitive in self.sensitive_fields):
                    masked_params[key] = '***MASKED***'
                    if 'sensitive_param' not in event['masked_fields']:
                        event['masked_fields'].append('sensitive_param')
                else:
                    # 脱敏值
                    masked_value = str(value)
                    for mask_type, (pattern, replacement) in mask_patterns.items():
                        if pattern.search(masked_value):
                            if callable(replacement):
                                masked_value = pattern.sub(replacement, masked_value)
                            else:
                                masked_value = pattern.sub(replacement, masked_value)
                            
                            if mask_type not in event['masked_fields']:
                                event['masked_fields'].append(mask_type)
                                
                    masked_params[key] = masked_value
                    
            event['metadata']['masked_query_params'] = masked_params
            
    def _create_error_event(self, original: Dict[str, Any], error: str) -> Dict[str, Any]:
        """创建错误事件"""
        return {
            'event_id': str(uuid.uuid4()),
            'timestamp': datetime.now(timezone.utc),
            'tenant': original.get('tenant', 'default'),
            'log_type': 'error',
            'severity': 'error',
            'message': f"标准化失败: {error}",
            'raw_message': original.get('raw_message', ''),
            'decoded_fields': {},
            'masked_fields': [],
            'metadata': {
                'error': error,
                'original_event': original
            }
        }

def create_normalizer() -> LogNormalizer:
    """创建日志标准化器实例"""
    return LogNormalizer()