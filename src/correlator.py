"""
事件关联模块
实现滑动窗口关联、去重抑制和严重级别升级
"""

import time
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import defaultdict, deque
import uuid
import logging

from .config import get_config

logger = logging.getLogger(__name__)

class EventCorrelator:
    """事件关联器"""
    
    def __init__(self):
        self.config = get_config()
        self.correlation_config = self.config.get_correlation_config()
        
        # 配置参数
        self.window_seconds = self.correlation_config.get("window_seconds", 60)
        self.max_events_per_window = self.correlation_config.get("max_events_per_window", 1000)
        self.correlation_fields = self.correlation_config.get("correlation_fields", ["src_ip", "user_id", "session_token"])
        
        # 严重级别升级配置
        self.severity_escalation = self.correlation_config.get("severity_escalation", {
            "multiple_rules": 1,
            "multiple_types": 2
        })
        
        # 存储结构
        self.event_windows = defaultdict(lambda: deque())  # 按关联键分组的事件窗口
        self.duplicate_cache = {}  # 去重缓存
        self.suppression_list = defaultdict(lambda: deque())  # 抑制列表
        self.ttl_cache = {}  # TTL缓存
        
        # 线程锁
        self.lock = threading.RLock()
        
        # 启动清理线程
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
        
    def correlate(self, detection_result: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        """关联事件并生成信号"""
        try:
            with self.lock:
                # 生成关联键
                correlation_keys = self._generate_correlation_keys(event)
                
                # 检查去重
                if self._is_duplicate(detection_result, event):
                    return None
                    
                # 检查抑制
                if self._is_suppressed(detection_result, event):
                    return None
                    
                # 添加到窗口
                correlation_id = str(uuid.uuid4())
                window_events = self._add_to_window(detection_result, event, correlation_keys, correlation_id)
                
                # 分析关联
                correlation_analysis = self._analyze_correlation(window_events, correlation_keys)
                
                # 生成信号
                signal = self._generate_signal(detection_result, event, correlation_analysis, correlation_id)
                
                # 更新抑制列表
                self._update_suppression(signal, event)
                
                return signal
                
        except Exception as e:
            logger.error(f"事件关联失败: {e}")
            return self._generate_error_signal(detection_result, event, str(e))
            
    def _generate_correlation_keys(self, event: Dict[str, Any]) -> List[str]:
        """生成关联键"""
        keys = []
        
        for field in self.correlation_fields:
            value = event.get(field)
            if value:
                keys.append(f"{field}:{str(value)}")
                
        # 如果没有关联键，使用默认键
        if not keys:
            keys.append("default:unknown")
            
        return keys
        
    def _is_duplicate(self, detection_result: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """检查是否为重复事件"""
        # 生成去重键
        dedup_key = self._generate_dedup_key(detection_result, event)
        
        current_time = time.time()
        
        # 检查缓存
        if dedup_key in self.duplicate_cache:
            last_time, count = self.duplicate_cache[dedup_key]
            
            # 如果在窗口内且未超过阈值
            if current_time - last_time < self.window_seconds:
                if count < 5:  # 最多允许5次重复
                    self.duplicate_cache[dedup_key] = (current_time, count + 1)
                    return False
                else:
                    return True  # 超过阈值，抑制
            else:
                # 超出窗口，重置
                self.duplicate_cache[dedup_key] = (current_time, 1)
                return False
        else:
            # 新事件
            self.duplicate_cache[dedup_key] = (current_time, 1)
            return False
            
    def _generate_dedup_key(self, detection_result: Dict[str, Any], event: Dict[str, Any]) -> str:
        """生成去重键"""
        key_parts = [
            str(event.get('tenant', 'default')),
            str(event.get('src_ip', 'unknown')),
            ','.join(sorted([str(t) for t in detection_result.get('threat_types', [])])),
            ','.join(sorted([str(r) for r in detection_result.get('matched_rules', [])]))
        ]
        
        return '|'.join(key_parts)
        
    def _is_suppressed(self, detection_result: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """检查是否被抑制"""
        src_ip = event.get('src_ip')
        if not src_ip:
            return False
            
        current_time = time.time()
        
        # 检查IP是否在抑制列表中
        if src_ip in self.ttl_cache:
            expiry_time = self.ttl_cache[src_ip]
            if current_time < expiry_time:
                return True
            else:
                # 过期，移除
                del self.ttl_cache[src_ip]
                
        return False
        
    def _add_to_window(self, detection_result: Dict[str, Any], event: Dict[str, Any], 
                      correlation_keys: List[str], correlation_id: str) -> List[Dict[str, Any]]:
        """添加事件到窗口"""
        current_time = time.time()
        
        # 创建窗口事件
        window_event = {
            'correlation_id': correlation_id,
            'timestamp': current_time,
            'detection_result': detection_result,
            'event': event
        }
        
        # 添加到所有相关窗口
        all_events = []
        
        for key in correlation_keys:
            window = self.event_windows[key]
            
            # 清理过期事件
            cutoff_time = current_time - self.window_seconds
            while window and window[0]['timestamp'] < cutoff_time:
                window.popleft()
                
            # 添加新事件
            window.append(window_event)
            
            # 限制窗口大小
            while len(window) > self.max_events_per_window:
                window.popleft()
                
            # 收集当前窗口的所有事件
            all_events.extend(list(window))
            
        # 去重
        seen_ids = set()
        unique_events = []
        for evt in all_events:
            if evt['correlation_id'] not in seen_ids:
                seen_ids.add(evt['correlation_id'])
                unique_events.append(evt)
                
        return unique_events
        
    def _analyze_correlation(self, window_events: List[Dict[str, Any]], 
                           correlation_keys: List[str]) -> Dict[str, Any]:
        """分析事件关联"""
        analysis = {
            'window_size': len(window_events),
            'correlation_keys': correlation_keys,
            'threat_types': set(),
            'matched_rules': set(),
            'severity_levels': set(),
            'unique_ips': set(),
            'unique_users': set(),
            'time_span': 0,
            'escalation_factors': []
        }
        
        if not window_events:
            return analysis
            
        # 统计信息
        timestamps = []
        
        for window_event in window_events:
            detection = window_event['detection_result']
            event = window_event['event']
            
            # 收集威胁类型和规则
            analysis['threat_types'].update(detection.get('threat_types', []))
            analysis['matched_rules'].update(detection.get('matched_rules', []))
            analysis['severity_levels'].add(detection.get('severity', 'info'))
            
            # 收集实体信息
            if event.get('src_ip'):
                analysis['unique_ips'].add(event['src_ip'])
            if event.get('user'):
                analysis['unique_users'].add(event['user'])
                
            timestamps.append(window_event['timestamp'])
            
        # 计算时间跨度
        if timestamps:
            analysis['time_span'] = max(timestamps) - min(timestamps)
            
        # 分析升级因子
        if len(analysis['matched_rules']) > 1:
            analysis['escalation_factors'].append('multiple_rules')
            
        if len(analysis['threat_types']) > 1:
            analysis['escalation_factors'].append('multiple_types')
            
        if len(analysis['unique_ips']) > 3:
            analysis['escalation_factors'].append('multiple_ips')
            
        if analysis['time_span'] < 10:  # 10秒内多次命中
            analysis['escalation_factors'].append('rapid_succession')
            
        # 转换集合为列表
        analysis['threat_types'] = list(analysis['threat_types'])
        analysis['matched_rules'] = list(analysis['matched_rules'])
        analysis['severity_levels'] = list(analysis['severity_levels'])
        analysis['unique_ips'] = list(analysis['unique_ips'])
        analysis['unique_users'] = list(analysis['unique_users'])
        
        return analysis
        
    def _generate_signal(self, detection_result: Dict[str, Any], event: Dict[str, Any],
                        correlation_analysis: Dict[str, Any], correlation_id: str) -> Dict[str, Any]:
        """生成信号"""
        # 基础信号结构
        signal = {
            'event_id': detection_result['event_id'],
            'ts': event['timestamp'].isoformat() if isinstance(event['timestamp'], datetime) else datetime.now(timezone.utc).isoformat(),
            'tenant': event['tenant'],
            'src_ip': event.get('src_ip'),
            'severity': detection_result['severity'],
            'threat_types': detection_result['threat_types'],
            'reason': detection_result['reason'],
            'matched_rules': detection_result['matched_rules'],
            'ml_score': detection_result.get('ml_score', 0.0),
            'window': f"{self.window_seconds}s",
            'correlation_id': correlation_id,
            'masked_fields': event.get('masked_fields', []),
            'sanitized_excerpt': self._generate_sanitized_excerpt(event),
            'action_planned': []
        }
        
        # 应用关联分析
        if correlation_analysis['window_size'] > 1:
            signal['window_hits'] = correlation_analysis['window_size']
            
            # 更新原因
            correlation_info = []
            if correlation_analysis['escalation_factors']:
                correlation_info.append(f"escalation: {', '.join(correlation_analysis['escalation_factors'])}")
            if correlation_analysis['window_size'] > 1:
                correlation_info.append(f"window_hits={correlation_analysis['window_size']}")
                
            if correlation_info:
                signal['reason'] += f"; {'; '.join(correlation_info)}"
                
        # 严重级别升级
        original_severity = signal['severity']
        escalated_severity = self._escalate_severity(original_severity, correlation_analysis)
        
        if escalated_severity != original_severity:
            signal['severity'] = escalated_severity
            signal['reason'] += f"; severity escalated from {original_severity} to {escalated_severity}"
            
        # 确定计划动作
        signal['action_planned'] = self._plan_actions(signal, event, correlation_analysis)
        
        return signal
        
    def _escalate_severity(self, original_severity: str, correlation_analysis: Dict[str, Any]) -> str:
        """升级严重级别"""
        severity_levels = ['info', 'low', 'medium', 'high', 'critical']
        current_level = severity_levels.index(original_severity) if original_severity in severity_levels else 0
        
        escalation = 0
        
        # 根据升级因子计算升级级别
        for factor in correlation_analysis['escalation_factors']:
            if factor in self.severity_escalation:
                escalation += self.severity_escalation[factor]
                
        # 应用升级
        new_level = min(current_level + escalation, len(severity_levels) - 1)
        
        return severity_levels[new_level]
        
    def _plan_actions(self, signal: Dict[str, Any], event: Dict[str, Any],
                     correlation_analysis: Dict[str, Any]) -> List[str]:
        """规划自动处置动作"""
        actions = []
        
        severity = signal['severity']
        threat_types = signal['threat_types']
        
        # 根据严重级别和威胁类型确定动作
        if severity in ['high', 'critical']:
            if signal.get('src_ip'):
                actions.append('block_ip')
                
        if severity in ['medium', 'high', 'critical']:
            if signal.get('src_ip'):
                actions.append('throttle_ip')
                
        # 敏感信息泄露需要日志脱敏
        if any(t in ['sensitive_data', 'pii'] for t in threat_types):
            actions.append('redact_log')
            
        # JWT或API密钥泄露需要吊销令牌
        if any('jwt' in rule or 'api' in rule for rule in signal['matched_rules']):
            actions.append('revoke_token')
            
        # 多次命中需要加强处置
        if correlation_analysis['window_size'] > 5:
            if 'block_ip' not in actions and signal.get('src_ip'):
                actions.append('block_ip')
                
        return actions
        
    def _generate_sanitized_excerpt(self, event: Dict[str, Any]) -> str:
        """生成脱敏摘要"""
        message = event.get('message', '')
        if not message:
            return ''
            
        # 确保message是字符串
        message = str(message)
            
        # 截取前200个字符
        excerpt = message[:200]
        
        # 简单脱敏
        import re
        
        # 脱敏邮箱
        excerpt = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***@***.***', excerpt)
        
        # 脱敏手机号
        excerpt = re.sub(r'(\+?86)?1[3-9]\d{9}', '***-****-****', excerpt)
        
        # 脱敏身份证
        excerpt = re.sub(r'\b[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[0-9Xx]\b', 
                        '****-**-**-****', excerpt)
        
        return excerpt
        
    def _update_suppression(self, signal: Dict[str, Any], event: Dict[str, Any]) -> None:
        """更新抑制列表"""
        # 高危事件的IP加入临时抑制列表
        if signal['severity'] in ['high', 'critical'] and signal.get('src_ip'):
            src_ip = signal['src_ip']
            
            # 设置TTL（根据严重级别）
            if signal['severity'] == 'critical':
                ttl_seconds = 3600  # 1小时
            else:
                ttl_seconds = 600   # 10分钟
                
            expiry_time = time.time() + ttl_seconds
            self.ttl_cache[src_ip] = expiry_time
            
            logger.info(f"IP {src_ip} 已加入抑制列表，TTL: {ttl_seconds}秒")
            
    def _generate_error_signal(self, detection_result: Dict[str, Any], 
                             event: Dict[str, Any], error: str) -> Dict[str, Any]:
        """生成错误信号"""
        return {
            'event_id': detection_result.get('event_id', str(uuid.uuid4())),
            'ts': datetime.now(timezone.utc).isoformat(),
            'tenant': event.get('tenant', 'default'),
            'src_ip': event.get('src_ip'),
            'severity': 'error',
            'threat_types': ['system_error'],
            'reason': f'关联处理失败: {error}',
            'matched_rules': [],
            'ml_score': 0.0,
            'window': f"{self.window_seconds}s",
            'correlation_id': str(uuid.uuid4()),
            'masked_fields': [],
            'sanitized_excerpt': '',
            'action_planned': []
        }
        
    def _cleanup_worker(self) -> None:
        """清理工作线程"""
        while True:
            try:
                time.sleep(60)  # 每分钟清理一次
                
                with self.lock:
                    current_time = time.time()
                    
                    # 清理过期的事件窗口
                    cutoff_time = current_time - self.window_seconds * 2
                    
                    for key in list(self.event_windows.keys()):
                        window = self.event_windows[key]
                        
                        # 移除过期事件
                        while window and window[0]['timestamp'] < cutoff_time:
                            window.popleft()
                            
                        # 如果窗口为空，删除键
                        if not window:
                            del self.event_windows[key]
                            
                    # 清理过期的去重缓存
                    expired_keys = []
                    for key, (timestamp, count) in self.duplicate_cache.items():
                        if current_time - timestamp > self.window_seconds * 2:
                            expired_keys.append(key)
                            
                    for key in expired_keys:
                        del self.duplicate_cache[key]
                        
                    # 清理过期的TTL缓存
                    expired_ips = []
                    for ip, expiry_time in self.ttl_cache.items():
                        if current_time > expiry_time:
                            expired_ips.append(ip)
                            
                    for ip in expired_ips:
                        del self.ttl_cache[ip]
                        
                    logger.debug(f"清理完成: 窗口={len(self.event_windows)}, 去重缓存={len(self.duplicate_cache)}, TTL缓存={len(self.ttl_cache)}")
                    
            except Exception as e:
                logger.error(f"清理工作失败: {e}")
                
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self.lock:
            return {
                'active_windows': len(self.event_windows),
                'total_events_in_windows': sum(len(window) for window in self.event_windows.values()),
                'duplicate_cache_size': len(self.duplicate_cache),
                'suppressed_ips': len(self.ttl_cache),
                'window_seconds': self.window_seconds,
                'max_events_per_window': self.max_events_per_window
            }

def create_correlator() -> EventCorrelator:
    """创建事件关联器实例"""
    return EventCorrelator()