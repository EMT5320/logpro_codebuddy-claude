"""
多源日志解析器
支持Nginx/Apache访问日志、JSON日志、数据库审计、容器日志、云审计等
"""

import re
import json
import gzip
import codecs
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Iterator, Union
from pathlib import Path
import logging
from urllib.parse import unquote

from .config import get_config

logger = logging.getLogger(__name__)

class LogParser:
    """多源日志解析器"""
    
    def __init__(self):
        self.config = get_config()
        self.max_line_length = self.config.get("system.max_line_length", 1048576)
        self.max_decode_rounds = self.config.get("system.max_decode_rounds", 5)
        
        # 编译正则表达式
        self._compile_patterns()
        
    def _compile_patterns(self):
        """编译常用正则表达式"""
        # Nginx日志格式
        self.nginx_pattern = re.compile(
            r'(?P<remote_addr>\S+) - (?P<remote_user>\S+) \[(?P<time_local>[^\]]+)\] '
            r'"(?P<request>[^"]*)" (?P<status>\d+) (?P<body_bytes_sent>\d+|-) '
            r'"(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
        )
        
        # Apache日志格式
        self.apache_pattern = re.compile(
            r'(?P<remote_host>\S+) (?P<remote_logname>\S+) (?P<remote_user>\S+) '
            r'\[(?P<timestamp>[^\]]+)\] "(?P<request>[^"]*)" '
            r'(?P<status>\d+) (?P<bytes_sent>\d+|-)'
        )
        
        # 时间格式
        self.time_formats = [
            "%d/%b/%Y:%H:%M:%S %z",  # Nginx/Apache
            "%Y-%m-%d %H:%M:%S",     # 标准格式
            "%Y-%m-%dT%H:%M:%S.%fZ", # ISO8601
            "%Y-%m-%dT%H:%M:%SZ",    # ISO8601简化
        ]
        
        # Kubernetes日志前缀
        self.k8s_pattern = re.compile(
            r'(?P<timestamp>\S+) (?P<stream>stdout|stderr) (?P<tag>[FP]) (?P<message>.*)'
        )
        
        # 容器标识
        self.container_pattern = re.compile(
            r'(?P<pod_name>[^/]+)/(?P<container_name>[^/]+)'
        )
        
    def parse_file(self, file_path: Union[str, Path], tenant: str = "default") -> Iterator[Dict[str, Any]]:
        """解析日志文件"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            logger.error(f"文件不存在: {file_path}")
            return
            
        try:
            if file_path.suffix == '.gz':
                with gzip.open(file_path, 'rt', encoding='utf-8', errors='replace') as f:
                    yield from self._parse_lines(f, tenant, str(file_path))
            else:
                with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                    yield from self._parse_lines(f, tenant, str(file_path))
                    
        except Exception as e:
            logger.error(f"解析文件失败 {file_path}: {e}")
            
    def parse_text(self, text: str, tenant: str = "default") -> Iterator[Dict[str, Any]]:
        """解析文本内容"""
        lines = text.split('\n')
        for line_no, line in enumerate(lines, 1):
            if line.strip():
                try:
                    event = self.parse_line(line, tenant)
                    if event:
                        event['line_number'] = line_no
                        yield event
                except Exception as e:
                    logger.warning(f"解析行失败 {line_no}: {e}")
                    
    def _parse_lines(self, file_obj, tenant: str, source: str) -> Iterator[Dict[str, Any]]:
        """解析文件行"""
        line_no = 0
        
        for line in file_obj:
            line_no += 1
            
            # 跳过空行和BOM
            line = line.strip()
            if not line or line.startswith('\ufeff'):
                continue
                
            # 检查行长度
            if len(line) > self.max_line_length:
                logger.warning(f"行过长被截断: {source}:{line_no}")
                line = line[:self.max_line_length]
                
            try:
                event = self.parse_line(line, tenant)
                if event:
                    event['source_file'] = source
                    event['line_number'] = line_no
                    yield event
                    
            except Exception as e:
                logger.warning(f"解析行失败 {source}:{line_no}: {e}")
                
    def parse_line(self, line: str, tenant: str = "default") -> Optional[Dict[str, Any]]:
        """解析单行日志"""
        # 尝试不同的解析器
        parsers = [
            self._parse_json,
            self._parse_nginx,
            self._parse_apache,
            self._parse_database,
            self._parse_container,
            self._parse_cloud_audit,
            self._parse_generic
        ]
        
        for parser in parsers:
            try:
                event = parser(line, tenant)
                if event:
                    return event
            except Exception as e:
                logger.debug(f"解析器失败 {parser.__name__}: {e}")
                continue
                
        return None
        
    def _parse_json(self, line: str, tenant: str) -> Optional[Dict[str, Any]]:
        """解析JSON日志"""
        try:
            data = json.loads(line)
            
            # 标准化字段
            event = {
                'tenant': tenant,
                'timestamp': self._extract_timestamp(data),
                'log_type': 'json',
                'raw_message': line,
                'parsed_data': data
            }
            
            # 提取常见字段
            self._extract_common_fields(event, data)
            
            return event
            
        except json.JSONDecodeError:
            return None
            
    def _parse_nginx(self, line: str, tenant: str) -> Optional[Dict[str, Any]]:
        """解析Nginx访问日志"""
        match = self.nginx_pattern.match(line)
        if not match:
            return None
            
        data = match.groupdict()
        
        event = {
            'tenant': tenant,
            'timestamp': self._parse_time(data['time_local']),
            'log_type': 'nginx',
            'raw_message': line,
            'src_ip': data['remote_addr'],
            'user': data['remote_user'] if data['remote_user'] != '-' else None,
            'request': data['request'],
            'status_code': int(data['status']),
            'bytes_sent': int(data['body_bytes_sent']) if data['body_bytes_sent'] != '-' else 0,
            'referer': data['http_referer'] if data['http_referer'] != '-' else None,
            'user_agent': data['http_user_agent'],
            'parsed_data': data
        }
        
        # 解析请求
        self._parse_request(event, data['request'])
        
        return event
        
    def _parse_apache(self, line: str, tenant: str) -> Optional[Dict[str, Any]]:
        """解析Apache访问日志"""
        match = self.apache_pattern.match(line)
        if not match:
            return None
            
        data = match.groupdict()
        
        event = {
            'tenant': tenant,
            'timestamp': self._parse_time(data['timestamp']),
            'log_type': 'apache',
            'raw_message': line,
            'src_ip': data['remote_host'],
            'user': data['remote_user'] if data['remote_user'] != '-' else None,
            'request': data['request'],
            'status_code': int(data['status']),
            'bytes_sent': int(data['bytes_sent']) if data['bytes_sent'] != '-' else 0,
            'parsed_data': data
        }
        
        # 解析请求
        self._parse_request(event, data['request'])
        
        return event
        
    def _parse_database(self, line: str, tenant: str) -> Optional[Dict[str, Any]]:
        """解析数据库审计日志"""
        # 检查是否包含SQL关键字
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER']
        line_upper = line.upper()
        
        if not any(keyword in line_upper for keyword in sql_keywords):
            return None
            
        event = {
            'tenant': tenant,
            'timestamp': datetime.now(timezone.utc),
            'log_type': 'database',
            'raw_message': line,
            'sql_statement': line.strip(),
            'parsed_data': {'statement': line.strip()}
        }
        
        # 提取SQL类型
        for keyword in sql_keywords:
            if keyword in line_upper:
                event['sql_type'] = keyword.lower()
                break
                
        return event
        
    def _parse_container(self, line: str, tenant: str) -> Optional[Dict[str, Any]]:
        """解析容器/Kubernetes日志"""
        # 检查Kubernetes日志格式
        k8s_match = self.k8s_pattern.match(line)
        if k8s_match:
            data = k8s_match.groupdict()
            
            event = {
                'tenant': tenant,
                'timestamp': self._parse_time(data['timestamp']),
                'log_type': 'kubernetes',
                'raw_message': line,
                'stream': data['stream'],
                'tag': data['tag'],
                'message': data['message'],
                'parsed_data': data
            }
            
            return event
            
        # 检查是否包含容器标识
        if 'pod/' in line or 'container/' in line:
            event = {
                'tenant': tenant,
                'timestamp': datetime.now(timezone.utc),
                'log_type': 'container',
                'raw_message': line,
                'message': line,
                'parsed_data': {}
            }
            
            # 提取Pod/Container信息
            container_match = self.container_pattern.search(line)
            if container_match:
                event['pod_name'] = container_match.group('pod_name')
                event['container_name'] = container_match.group('container_name')
                event['parsed_data'].update(container_match.groupdict())
                
            return event
            
        return None
        
    def _parse_cloud_audit(self, line: str, tenant: str) -> Optional[Dict[str, Any]]:
        """解析云审计日志"""
        # 检查是否包含审计关键字
        audit_keywords = ['user', 'principal', 'actor', 'resource', 'action', 'operation']
        line_lower = line.lower()
        
        if not any(keyword in line_lower for keyword in audit_keywords):
            return None
            
        event = {
            'tenant': tenant,
            'timestamp': datetime.now(timezone.utc),
            'log_type': 'cloud_audit',
            'raw_message': line,
            'message': line,
            'parsed_data': {}
        }
        
        # 简单的键值对提取
        pairs = re.findall(r'(\w+)[:=]\s*([^\s,]+)', line)
        for key, value in pairs:
            event['parsed_data'][key.lower()] = value
            
            # 映射到标准字段
            if key.lower() in ['user', 'principal', 'actor']:
                event['user'] = value
            elif key.lower() in ['resource', 'target', 'object']:
                event['resource'] = value
            elif key.lower() in ['action', 'operation', 'verb']:
                event['action'] = value
                
        return event
        
    def _parse_generic(self, line: str, tenant: str) -> Optional[Dict[str, Any]]:
        """通用日志解析"""
        event = {
            'tenant': tenant,
            'timestamp': datetime.now(timezone.utc),
            'log_type': 'generic',
            'raw_message': line,
            'message': line,
            'parsed_data': {}
        }
        
        return event
        
    def _extract_timestamp(self, data: Dict[str, Any]) -> datetime:
        """从数据中提取时间戳"""
        timestamp_fields = ['timestamp', 'time', '@timestamp', 'datetime', 'date']
        
        for field in timestamp_fields:
            if field in data:
                return self._parse_time(data[field])
                
        return datetime.now(timezone.utc)
        
    def _parse_time(self, time_str: str) -> datetime:
        """解析时间字符串"""
        if isinstance(time_str, (int, float)):
            return datetime.fromtimestamp(time_str, timezone.utc)
            
        time_str = str(time_str).strip()
        
        for fmt in self.time_formats:
            try:
                dt = datetime.strptime(time_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
                
        # 尝试ISO格式解析
        try:
            return datetime.fromisoformat(time_str.replace('Z', '+00:00'))
        except ValueError:
            pass
            
        logger.warning(f"无法解析时间: {time_str}")
        return datetime.now(timezone.utc)
        
    def _extract_common_fields(self, event: Dict[str, Any], data: Dict[str, Any]) -> None:
        """提取通用字段"""
        field_mappings = {
            'src_ip': ['remote_addr', 'client_ip', 'ip', 'source_ip'],
            'user': ['user', 'username', 'user_id', 'remote_user'],
            'user_agent': ['user_agent', 'useragent', 'ua'],
            'request': ['request', 'url', 'path'],
            'status_code': ['status', 'status_code', 'response_code'],
            'method': ['method', 'http_method', 'verb']
        }
        
        for target_field, source_fields in field_mappings.items():
            for source_field in source_fields:
                if source_field in data and data[source_field]:
                    event[target_field] = data[source_field]
                    break
                    
    def _parse_request(self, event: Dict[str, Any], request: str) -> None:
        """解析HTTP请求"""
        if not request or request == '-':
            return
            
        parts = request.split(' ', 2)
        if len(parts) >= 2:
            event['method'] = parts[0]
            event['path'] = parts[1]
            
            # URL解码
            try:
                event['decoded_path'] = unquote(parts[1])
            except Exception:
                event['decoded_path'] = parts[1]
                
            if len(parts) >= 3:
                event['protocol'] = parts[2]
                
        # 提取查询参数
        if '?' in request:
            try:
                path, query = request.split('?', 1)
                event['query_string'] = query
                
                # 解析参数
                params = {}
                for param in query.split('&'):
                    if '=' in param:
                        key, value = param.split('=', 1)
                        params[unquote(key)] = unquote(value)
                    else:
                        params[unquote(param)] = ''
                        
                event['query_params'] = params
                
            except Exception as e:
                logger.debug(f"解析查询参数失败: {e}")

def create_parser() -> LogParser:
    """创建日志解析器实例"""
    return LogParser()