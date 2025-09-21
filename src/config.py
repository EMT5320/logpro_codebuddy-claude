"""
配置管理模块
负责加载和管理系统配置，支持热加载
"""

import os
import yaml
import json
import threading
import time
from typing import Dict, Any, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class ConfigManager:
    """配置管理器，支持热加载"""
    
    def __init__(self, config_path: str = "config.yml"):
        self.config_path = Path(config_path)
        self.config: Dict[str, Any] = {}
        self.last_modified = 0
        self.lock = threading.RLock()
        self.load_config()
        
    def load_config(self) -> None:
        """加载配置文件"""
        try:
            with self.lock:
                if not self.config_path.exists():
                    logger.warning(f"配置文件不存在: {self.config_path}")
                    self._load_default_config()
                    return
                    
                stat = self.config_path.stat()
                if stat.st_mtime <= self.last_modified:
                    return
                    
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    if self.config_path.suffix.lower() == '.json':
                        self.config = json.load(f)
                    else:
                        self.config = yaml.safe_load(f) or {}
                        
                self.last_modified = stat.st_mtime
                logger.info(f"配置已加载: {self.config_path}")
                
        except Exception as e:
            logger.error(f"加载配置失败: {e}")
            if not self.config:
                self._load_default_config()
                
    def _load_default_config(self) -> None:
        """加载默认配置"""
        self.config = {
            "system": {
                "max_line_length": 1048576,
                "max_decode_rounds": 5,
                "concurrency": 4,
                "rate_limit": 10000,
                "memory_limit_mb": 600
            },
            "time": {
                "default_timezone": "UTC",
                "correlation_window": 60,
                "ttl_cleanup_interval": 300
            },
            "tenants": {
                "default": "system",
                "isolation": True
            },
            "ml": {
                "enabled": True,
                "model_type": "tfidf_lr",
                "threshold": 0.7
            },
            "actions": {
                "enabled": True,
                "dry_run": False
            },
            "api": {
                "host": "0.0.0.0",
                "port": 8080,
                "workers": 1
            }
        }
        
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置值，支持点分隔的嵌套键"""
        with self.lock:
            keys = key.split('.')
            value = self.config
            
            for k in keys:
                if isinstance(value, dict) and k in value:
                    value = value[k]
                else:
                    return default
                    
            return value
            
    def set(self, key: str, value: Any) -> None:
        """设置配置值"""
        with self.lock:
            keys = key.split('.')
            config = self.config
            
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
                
            config[keys[-1]] = value
            
    def reload(self) -> bool:
        """重新加载配置"""
        try:
            old_modified = self.last_modified
            self.last_modified = 0  # 强制重新加载
            self.load_config()
            return self.last_modified > old_modified
        except Exception as e:
            logger.error(f"重新加载配置失败: {e}")
            return False
            
    def get_rules(self) -> Dict[str, Any]:
        """获取检测规则"""
        return self.get("rules", {})
        
    def get_ml_config(self) -> Dict[str, Any]:
        """获取机器学习配置"""
        return self.get("ml", {})
        
    def get_action_config(self) -> Dict[str, Any]:
        """获取动作配置"""
        return self.get("actions", {})
        
    def get_correlation_config(self) -> Dict[str, Any]:
        """获取关联配置"""
        return self.get("correlation", {})
        
    def is_action_enabled(self, action_type: str) -> bool:
        """检查动作是否启用"""
        return (self.get("actions.enabled", True) and 
                self.get(f"actions.{action_type}.enabled", True))
                
    def is_dry_run(self) -> bool:
        """检查是否为演练模式"""
        return self.get("actions.dry_run", False)

# 全局配置实例
config = ConfigManager()

def get_config() -> ConfigManager:
    """获取全局配置实例"""
    return config

def reload_config() -> bool:
    """重新加载全局配置"""
    return config.reload()