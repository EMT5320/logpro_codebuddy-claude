"""
自动响应模块
实现动作总线和各种自动处置动作的执行
"""

import time
import uuid
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set
from collections import defaultdict, deque
import logging

from .config import get_config

logger = logging.getLogger(__name__)

class ActionBus:
    """动作总线，负责执行和管理自动处置动作"""
    
    def __init__(self):
        self.config = get_config()
        self.action_config = self.config.get_action_config()
        
        # 动作执行器
        self.executors = {
            'block_ip': IPBlocker(self.config),
            'throttle_ip': IPThrottler(self.config),
            'revoke_token': TokenRevoker(self.config),
            'redact_log': LogRedactor(self.config)
        }
        
        # 动作历史
        self.action_history = deque(maxlen=10000)
        self.lock = threading.RLock()
        
        # 幂等性缓存
        self.idempotent_cache = {}
        
    def execute_actions(self, signal: Dict[str, Any]) -> List[Dict[str, Any]]:
        """执行信号中计划的动作"""
        actions_executed = []
        
        if not self.action_config.get("enabled", True):
            logger.info("自动处置已禁用")
            return actions_executed
            
        planned_actions = signal.get('action_planned', [])
        if not planned_actions:
            return actions_executed
            
        for action_type in planned_actions:
            try:
                action_result = self._execute_single_action(
                    action_type, signal
                )
                if action_result:
                    actions_executed.append(action_result)
                    
            except Exception as e:
                logger.error(f"执行动作失败 {action_type}: {e}")
                
                # 记录失败的动作
                failed_action = {
                    'action_id': str(uuid.uuid4()),
                    'ts': datetime.now(timezone.utc).isoformat(),
                    'correlation_id': signal.get('correlation_id'),
                    'kind': action_type,
                    'target': {},
                    'status': 'failed',
                    'reason': f'执行失败: {e}',
                    'idempotent_key': ''
                }
                actions_executed.append(failed_action)
                
        return actions_executed
        
    def _execute_single_action(self, action_type: str, signal: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """执行单个动作"""
        if action_type not in self.executors:
            logger.warning(f"未知动作类型: {action_type}")
            return None
            
        executor = self.executors[action_type]
        
        # 检查动作是否启用
        if not self.config.is_action_enabled(action_type):
            logger.info(f"动作已禁用: {action_type}")
            return None
            
        # 生成幂等键
        idempotent_key = self._generate_idempotent_key(action_type, signal)
        
        # 检查幂等性
        if self._is_duplicate_action(idempotent_key):
            logger.debug(f"跳过重复动作: {idempotent_key}")
            return {
                'action_id': str(uuid.uuid4()),
                'ts': datetime.now(timezone.utc).isoformat(),
                'correlation_id': signal.get('correlation_id'),
                'kind': action_type,
                'target': {},
                'status': 'skipped',
                'reason': '重复动作，已跳过',
                'idempotent_key': idempotent_key
            }
            
        # 执行动作
        try:
            result = executor.execute(signal)
            
            # 记录到幂等缓存
            self._record_action(idempotent_key)
            
            # 添加到历史记录
            with self.lock:
                self.action_history.append(result)
                
            return result
            
        except Exception as e:
            logger.error(f"动作执行失败 {action_type}: {e}")
            raise
            
    def _generate_idempotent_key(self, action_type: str, signal: Dict[str, Any]) -> str:
        """生成幂等键"""
        key_parts = [
            signal.get('tenant', 'default'),
            action_type,
            signal.get('src_ip', 'unknown')
        ]
        
        # 根据动作类型添加特定字段
        if action_type in ['block_ip', 'throttle_ip']:
            key_parts.append(signal.get('src_ip', 'unknown'))
        elif action_type == 'revoke_token':
            # 这里需要从信号中提取token信息
            key_parts.append('token_placeholder')
            
        return ':'.join(key_parts)
        
    def _is_duplicate_action(self, idempotent_key: str) -> bool:
        """检查是否为重复动作"""
        current_time = time.time()
        
        if idempotent_key in self.idempotent_cache:
            last_time = self.idempotent_cache[idempotent_key]
            # 5分钟内的相同动作视为重复
            if current_time - last_time < 300:
                return True
                
        return False
        
    def _record_action(self, idempotent_key: str) -> None:
        """记录动作执行"""
        self.idempotent_cache[idempotent_key] = time.time()
        
    def get_recent_actions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """获取最近的动作记录"""
        with self.lock:
            return list(self.action_history)[-limit:]

class BaseActionExecutor:
    """动作执行器基类"""
    
    def __init__(self, config):
        self.config = config
        
    def execute(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        """执行动作，子类需要实现"""
        raise NotImplementedError

class IPBlocker(BaseActionExecutor):
    """IP封禁执行器"""
    
    def __init__(self, config):
        super().__init__(config)
        self.blocked_ips = {}  # IP -> 过期时间
        self.lock = threading.RLock()
        
    def execute(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        """执行IP封禁"""
        src_ip = signal.get('src_ip')
        if not src_ip:
            raise ValueError("缺少源IP地址")
            
        # 检查白名单
        whitelist = self.config.get("whitelist.ips", [])
        if src_ip in whitelist:
            return self._create_action_result(
                signal, 'block_ip', {'ip': src_ip}, 
                'skipped', f'IP {src_ip} 在白名单中'
            )
            
        # 确定TTL
        severity = signal.get('severity', 'medium')
        if severity == 'critical':
            ttl_sec = self.config.get("actions.block_ip.max_ttl", 86400)
        elif severity == 'high':
            ttl_sec = self.config.get("actions.block_ip.default_ttl", 600) * 2
        else:
            ttl_sec = self.config.get("actions.block_ip.default_ttl", 600)
            
        # 执行封禁
        if self.config.is_dry_run():
            status = 'simulated'
            reason = f'模拟封禁IP {src_ip}，TTL: {ttl_sec}秒'
        else:
            with self.lock:
                expiry_time = time.time() + ttl_sec
                self.blocked_ips[src_ip] = expiry_time
                
            status = 'executed'
            reason = f'已封禁IP {src_ip}，TTL: {ttl_sec}秒'
            
        logger.info(reason)
        
        return self._create_action_result(
            signal, 'block_ip', 
            {'ip': src_ip, 'ttl_sec': ttl_sec},
            status, reason
        )
        
    def is_blocked(self, ip: str) -> bool:
        """检查IP是否被封禁"""
        with self.lock:
            if ip in self.blocked_ips:
                if time.time() < self.blocked_ips[ip]:
                    return True
                else:
                    # 过期，移除
                    del self.blocked_ips[ip]
                    
        return False
        
    def _create_action_result(self, signal: Dict[str, Any], kind: str, 
                            target: Dict[str, Any], status: str, reason: str) -> Dict[str, Any]:
        """创建动作结果"""
        return {
            'action_id': str(uuid.uuid4()),
            'ts': datetime.now(timezone.utc).isoformat(),
            'correlation_id': signal.get('correlation_id'),
            'kind': kind,
            'target': target,
            'status': status,
            'reason': reason,
            'idempotent_key': f"{signal.get('tenant')}:{kind}:{target.get('ip', 'unknown')}"
        }

class IPThrottler(BaseActionExecutor):
    """IP限速执行器"""
    
    def __init__(self, config):
        super().__init__(config)
        self.throttled_ips = {}  # IP -> (限速配置, 过期时间)
        self.lock = threading.RLock()
        
    def execute(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        """执行IP限速"""
        src_ip = signal.get('src_ip')
        if not src_ip:
            raise ValueError("缺少源IP地址")
            
        # 限速配置
        rate_limit = self.config.get("actions.throttle_ip.rate_limit", 10)
        ttl_sec = self.config.get("actions.throttle_ip.default_ttl", 300)
        
        # 执行限速
        if self.config.is_dry_run():
            status = 'simulated'
            reason = f'模拟限速IP {src_ip}，限制: {rate_limit}请求/分钟'
        else:
            with self.lock:
                expiry_time = time.time() + ttl_sec
                self.throttled_ips[src_ip] = (rate_limit, expiry_time)
                
            status = 'executed'
            reason = f'已限速IP {src_ip}，限制: {rate_limit}请求/分钟'
            
        logger.info(reason)
        
        return {
            'action_id': str(uuid.uuid4()),
            'ts': datetime.now(timezone.utc).isoformat(),
            'correlation_id': signal.get('correlation_id'),
            'kind': 'throttle_ip',
            'target': {'ip': src_ip, 'rate_limit': rate_limit, 'ttl_sec': ttl_sec},
            'status': status,
            'reason': reason,
            'idempotent_key': f"{signal.get('tenant')}:throttle_ip:{src_ip}"
        }

class TokenRevoker(BaseActionExecutor):
    """令牌吊销执行器"""
    
    def __init__(self, config):
        super().__init__(config)
        self.revoked_tokens = set()
        self.lock = threading.RLock()
        
    def execute(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        """执行令牌吊销"""
        # 从匹配的规则中提取令牌信息
        token_info = self._extract_token_info(signal)
        
        if not token_info:
            return {
                'action_id': str(uuid.uuid4()),
                'ts': datetime.now(timezone.utc).isoformat(),
                'correlation_id': signal.get('correlation_id'),
                'kind': 'revoke_token',
                'target': {},
                'status': 'skipped',
                'reason': '未找到可吊销的令牌',
                'idempotent_key': f"{signal.get('tenant')}:revoke_token:none"
            }
            
        # 执行吊销
        if self.config.is_dry_run():
            status = 'simulated'
            reason = f'模拟吊销令牌: {token_info["type"]}'
        else:
            with self.lock:
                self.revoked_tokens.add(token_info['hash'])
                
            status = 'executed'
            reason = f'已吊销令牌: {token_info["type"]}'
            
        logger.info(reason)
        
        return {
            'action_id': str(uuid.uuid4()),
            'ts': datetime.now(timezone.utc).isoformat(),
            'correlation_id': signal.get('correlation_id'),
            'kind': 'revoke_token',
            'target': {'token_type': token_info['type'], 'token_hash': token_info['hash']},
            'status': status,
            'reason': reason,
            'idempotent_key': f"{signal.get('tenant')}:revoke_token:{token_info['hash']}"
        }
        
    def _extract_token_info(self, signal: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """从信号中提取令牌信息"""
        matched_rules = signal.get('matched_rules', [])
        
        for rule_id in matched_rules:
            if 'JWT' in rule_id:
                return {'type': 'jwt', 'hash': 'jwt_hash_placeholder'}
            elif 'APIKEY' in rule_id:
                return {'type': 'api_key', 'hash': 'apikey_hash_placeholder'}
                
        return None

class LogRedactor(BaseActionExecutor):
    """日志脱敏执行器"""
    
    def execute(self, signal: Dict[str, Any]) -> Dict[str, Any]:
        """执行日志脱敏"""
        # 获取脱敏字段
        redact_fields = self.config.get("actions.redact_log.fields", [])
        masked_fields = signal.get('masked_fields', [])
        
        # 执行脱敏
        if self.config.is_dry_run():
            status = 'simulated'
            reason = f'模拟脱敏字段: {", ".join(masked_fields)}'
        else:
            # 实际的脱敏逻辑会在日志输出时应用
            status = 'executed'
            reason = f'已标记脱敏字段: {", ".join(masked_fields)}'
            
        logger.info(reason)
        
        return {
            'action_id': str(uuid.uuid4()),
            'ts': datetime.now(timezone.utc).isoformat(),
            'correlation_id': signal.get('correlation_id'),
            'kind': 'redact_log',
            'target': {'fields': masked_fields},
            'status': status,
            'reason': reason,
            'idempotent_key': f"{signal.get('tenant')}:redact_log:{signal.get('event_id')}"
        }

def create_action_bus() -> ActionBus:
    """创建动作总线实例"""
    return ActionBus()