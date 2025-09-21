"""
威胁检测模块
实现规则检测、机器学习检测和异常检测的混合策略
"""

import re
import json
import pickle
import numpy as np
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime, timezone
from pathlib import Path
import logging
from collections import defaultdict, deque
import threading
import time

# 机器学习相关
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support

from .config import get_config

logger = logging.getLogger(__name__)

class ThreatDetector:
    """威胁检测器"""
    
    def __init__(self):
        self.config = get_config()
        self.rules = {}
        self.ml_model = None
        self.vectorizer = None
        self.anomaly_detector = None
        self.baseline_data = deque(maxlen=10000)  # 基线数据
        
        # 线程锁
        self.lock = threading.RLock()
        
        # 加载规则和模型
        self._load_rules()
        self._initialize_ml()
        
    def _load_rules(self) -> None:
        """加载检测规则"""
        rules_config = self.config.get_rules()
        
        with self.lock:
            self.rules = {}
            
            for category, rule_list in rules_config.items():
                if not isinstance(rule_list, list):
                    continue
                    
                compiled_rules = []
                for rule in rule_list:
                    try:
                        compiled_rule = {
                            'id': rule['id'],
                            'pattern': re.compile(rule['pattern'], re.IGNORECASE | re.MULTILINE),
                            'severity': rule['severity'],
                            'description': rule['description'],
                            'category': category
                        }
                        compiled_rules.append(compiled_rule)
                        
                    except Exception as e:
                        logger.error(f"编译规则失败 {rule.get('id', 'unknown')}: {e}")
                        
                self.rules[category] = compiled_rules
                
        logger.info(f"已加载 {sum(len(rules) for rules in self.rules.values())} 条检测规则")
        
    def _initialize_ml(self) -> None:
        """初始化机器学习模型"""
        ml_config = self.config.get_ml_config()
        
        if not ml_config.get("enabled", True):
            logger.info("机器学习检测已禁用")
            return
            
        try:
            # 初始化向量化器
            self.vectorizer = TfidfVectorizer(
                max_features=ml_config.get("max_features", 10000),
                ngram_range=(1, 3),
                analyzer='char_wb',
                lowercase=True,
                stop_words=None
            )
            
            # 初始化分类器
            self.ml_model = LogisticRegression(
                random_state=42,
                max_iter=1000,
                class_weight='balanced'
            )
            
            # 初始化异常检测器
            anomaly_config = self.config.get("anomaly", {})
            if anomaly_config.get("enabled", True):
                algorithm = anomaly_config.get("algorithm", "isolation_forest")
                
                if algorithm == "isolation_forest":
                    self.anomaly_detector = IsolationForest(
                        contamination=anomaly_config.get("contamination", 0.1),
                        random_state=42,
                        n_estimators=100
                    )
                elif algorithm == "one_class_svm":
                    self.anomaly_detector = OneClassSVM(
                        nu=anomaly_config.get("contamination", 0.1),
                        kernel='rbf',
                        gamma='scale'
                    )
                    
            logger.info("机器学习模型初始化完成")
            
        except Exception as e:
            logger.error(f"初始化机器学习模型失败: {e}")
            
    def detect(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """检测威胁"""
        detection_result = {
            'event_id': event['event_id'],
            'timestamp': event['timestamp'],
            'tenant': event['tenant'],
            'src_ip': event.get('src_ip'),
            'severity': 'info',
            'threat_types': [],
            'matched_rules': [],
            'ml_score': 0.0,
            'anomaly_score': 0.0,
            'is_threat': False,
            'reason': '',
            'confidence': 0.0
        }
        
        try:
            # 规则检测
            rule_results = self._detect_by_rules(event)
            
            # 机器学习检测
            ml_results = self._detect_by_ml(event)
            
            # 异常检测
            anomaly_results = self._detect_anomaly(event)
            
            # 合并结果
            self._merge_detection_results(detection_result, rule_results, ml_results, anomaly_results)
            
            # 更新基线数据
            self._update_baseline(event, detection_result)
            
            return detection_result
            
        except Exception as e:
            logger.error(f"威胁检测失败: {e}")
            detection_result['reason'] = f"检测失败: {e}"
            return detection_result
            
    def _detect_by_rules(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """基于规则的检测"""
        results = {
            'matched_rules': [],
            'threat_types': [],
            'max_severity': 'info',
            'confidence': 0.0
        }
        
        # 提取检测文本
        text_fields = self._extract_text_for_detection(event)
        
        # 遍历所有规则
        for category, rules in self.rules.items():
            for rule in rules:
                for field_name, text in text_fields.items():
                    if rule['pattern'].search(text):
                        results['matched_rules'].append(rule['id'])
                        
                        if category not in results['threat_types']:
                            results['threat_types'].append(category)
                            
                        # 更新最高严重级别
                        if self._severity_level(rule['severity']) > self._severity_level(results['max_severity']):
                            results['max_severity'] = rule['severity']
                            
                        logger.debug(f"规则命中: {rule['id']} in {field_name}")
                        break
                        
        # 计算置信度
        if results['matched_rules']:
            results['confidence'] = min(1.0, len(results['matched_rules']) * 0.3)
            
        return results
        
    def _detect_by_ml(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """基于机器学习的检测"""
        results = {
            'ml_score': 0.0,
            'is_malicious': False,
            'confidence': 0.0
        }
        
        if not self.ml_model or not self.vectorizer:
            return results
            
        try:
            # 提取特征文本
            feature_text = self._extract_feature_text(event)
            
            # 向量化
            features = self.vectorizer.transform([feature_text])
            
            # 预测
            if hasattr(self.ml_model, 'predict_proba'):
                proba = self.ml_model.predict_proba(features)[0]
                if len(proba) > 1:
                    results['ml_score'] = proba[1]  # 恶意类别的概率
                    results['is_malicious'] = results['ml_score'] > self.config.get("ml.threshold", 0.7)
                    results['confidence'] = results['ml_score']
                    
        except Exception as e:
            logger.debug(f"机器学习检测失败: {e}")
            
        return results
        
    def _detect_anomaly(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """异常检测"""
        results = {
            'anomaly_score': 0.0,
            'is_anomaly': False,
            'confidence': 0.0
        }
        
        # 暂时禁用异常检测以避免错误
        return results
        
    def _extract_text_for_detection(self, event: Dict[str, Any]) -> Dict[str, str]:
        """提取用于检测的文本字段"""
        text_fields = {}
        
        # 主要字段
        for field in ['message', 'path', 'query_string', 'user_agent']:
            if field in event and event[field]:
                text_fields[field] = str(event[field])
                
        # 解码后的字段
        if 'decoded_fields' in event:
            for field, value in event['decoded_fields'].items():
                text_fields[f"decoded_{field}"] = str(value)
                
        # 查询参数
        if 'metadata' in event and 'query_params' in event['metadata']:
            params_text = ' '.join([
                f"{k}={v}" for k, v in event['metadata']['query_params'].items()
            ])
            text_fields['query_params'] = params_text
            
        # SQL语句
        if 'metadata' in event and 'sql_statement' in event['metadata']:
            text_fields['sql_statement'] = event['metadata']['sql_statement']
            
        return text_fields
        
    def _extract_feature_text(self, event: Dict[str, Any]) -> str:
        """提取机器学习特征文本"""
        text_parts = []
        
        # 合并所有文本字段
        text_fields = self._extract_text_for_detection(event)
        for text in text_fields.values():
            if text:
                text_parts.append(text)
                
        return ' '.join(text_parts)
        
    def _extract_numerical_features(self, event: Dict[str, Any]) -> List[float]:
        """提取数值特征"""
        features = []
        
        # 基础特征
        features.append(len(event.get('message', '')))  # 消息长度
        features.append(len(event.get('path', '')))     # 路径长度
        features.append(event.get('status_code', 0))    # 状态码
        
        # 字符统计特征
        message = event.get('message', '')
        if message:
            features.extend([
                message.count('='),      # 等号数量
                message.count('&'),      # 与号数量
                message.count('%'),      # 百分号数量
                message.count('<'),      # 小于号数量
                message.count('>'),      # 大于号数量
                message.count("'"),      # 单引号数量
                message.count('"'),      # 双引号数量
                message.count('('),      # 左括号数量
                message.count(')'),      # 右括号数量
            ])
        else:
            features.extend([0] * 9)
            
        # 时间特征
        if isinstance(event.get('timestamp'), datetime):
            ts = event['timestamp']
            features.extend([
                ts.hour,           # 小时
                ts.weekday(),      # 星期
                ts.minute,         # 分钟
            ])
        else:
            features.extend([0, 0, 0])
            
        return features
        
    def _merge_detection_results(self, result: Dict[str, Any], 
                               rule_results: Dict[str, Any],
                               ml_results: Dict[str, Any],
                               anomaly_results: Dict[str, Any]) -> None:
        """合并检测结果"""
        # 规则检测结果
        result['matched_rules'] = rule_results['matched_rules']
        result['threat_types'] = rule_results['threat_types']
        
        # 机器学习结果
        result['ml_score'] = ml_results['ml_score']
        
        # 异常检测结果
        result['anomaly_score'] = anomaly_results['anomaly_score']
        
        # 判断是否为威胁
        is_rule_threat = len(rule_results['matched_rules']) > 0
        is_ml_threat = ml_results['is_malicious']
        is_anomaly_threat = anomaly_results['is_anomaly']
        
        result['is_threat'] = is_rule_threat or is_ml_threat or is_anomaly_threat
        
        # 确定严重级别
        if is_rule_threat:
            result['severity'] = rule_results['max_severity']
        elif is_ml_threat:
            if ml_results['ml_score'] > 0.9:
                result['severity'] = 'high'
            elif ml_results['ml_score'] > 0.7:
                result['severity'] = 'medium'
            else:
                result['severity'] = 'low'
        elif is_anomaly_threat:
            result['severity'] = 'low'
            
        # 计算综合置信度
        confidences = [
            rule_results['confidence'],
            ml_results['confidence'],
            anomaly_results['confidence']
        ]
        result['confidence'] = max(confidences) if confidences else 0.0
        
        # 生成原因说明
        reasons = []
        if rule_results['matched_rules']:
            reasons.append(f"matched rules: {', '.join(rule_results['matched_rules'])}")
        if ml_results['is_malicious']:
            reasons.append(f"ml_score={ml_results['ml_score']:.2f}")
        if anomaly_results['is_anomaly']:
            reasons.append(f"anomaly_score={anomaly_results['anomaly_score']:.2f}")
            
        result['reason'] = '; '.join(reasons) if reasons else 'no threat detected'
        
    def _severity_level(self, severity: str) -> int:
        """获取严重级别数值"""
        levels = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return levels.get(severity.lower(), 0)
        
    def _update_baseline(self, event: Dict[str, Any], detection_result: Dict[str, Any]) -> None:
        """更新基线数据"""
        if not detection_result['is_threat']:
            # 只有正常事件才加入基线
            features = self._extract_numerical_features(event)
            if features:
                self.baseline_data.append(features)
                
                # 定期重训练异常检测器
                if len(self.baseline_data) >= 1000 and len(self.baseline_data) % 500 == 0:
                    self._retrain_anomaly_detector()
                    
    def _retrain_anomaly_detector(self) -> None:
        """重新训练异常检测器"""
        if not self.anomaly_detector or len(self.baseline_data) < 100:
            return
            
        try:
            with self.lock:
                data = np.array(list(self.baseline_data))
                self.anomaly_detector.fit(data)
                logger.info(f"异常检测器已重新训练，使用 {len(data)} 个样本")
                
        except Exception as e:
            logger.error(f"重新训练异常检测器失败: {e}")
            
    def train_ml_model(self, training_data: List[Dict[str, Any]], 
                      labels: List[int]) -> Dict[str, Any]:
        """训练机器学习模型"""
        if not self.vectorizer or not self.ml_model:
            return {'success': False, 'error': '模型未初始化'}
            
        try:
            # 提取特征文本
            texts = [self._extract_feature_text(event) for event in training_data]
            
            # 向量化
            X = self.vectorizer.fit_transform(texts)
            y = np.array(labels)
            
            # 分割数据
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # 训练模型
            self.ml_model.fit(X_train, y_train)
            
            # 评估模型
            y_pred = self.ml_model.predict(X_test)
            y_proba = self.ml_model.predict_proba(X_test)[:, 1] if hasattr(self.ml_model, 'predict_proba') else None
            
            # 计算指标
            precision, recall, f1, _ = precision_recall_fscore_support(y_test, y_pred, average='binary')
            
            results = {
                'success': True,
                'train_samples': len(X_train),
                'test_samples': len(X_test),
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'classification_report': classification_report(y_test, y_pred),
                'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
            }
            
            if y_proba is not None:
                from sklearn.metrics import roc_auc_score
                results['auc_score'] = roc_auc_score(y_test, y_proba)
                
            logger.info(f"模型训练完成: F1={f1:.3f}, Precision={precision:.3f}, Recall={recall:.3f}")
            
            return results
            
        except Exception as e:
            logger.error(f"训练机器学习模型失败: {e}")
            return {'success': False, 'error': str(e)}
            
    def save_model(self, model_path: str) -> bool:
        """保存模型"""
        try:
            model_data = {
                'vectorizer': self.vectorizer,
                'ml_model': self.ml_model,
                'anomaly_detector': self.anomaly_detector,
                'baseline_data': list(self.baseline_data)
            }
            
            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)
                
            logger.info(f"模型已保存到: {model_path}")
            return True
            
        except Exception as e:
            logger.error(f"保存模型失败: {e}")
            return False
            
    def load_model(self, model_path: str) -> bool:
        """加载模型"""
        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
                
            with self.lock:
                self.vectorizer = model_data.get('vectorizer')
                self.ml_model = model_data.get('ml_model')
                self.anomaly_detector = model_data.get('anomaly_detector')
                
                baseline_data = model_data.get('baseline_data', [])
                self.baseline_data = deque(baseline_data, maxlen=10000)
                
            logger.info(f"模型已从 {model_path} 加载")
            return True
            
        except Exception as e:
            logger.error(f"加载模型失败: {e}")
            return False
            
    def reload_rules(self) -> bool:
        """重新加载规则"""
        try:
            self._load_rules()
            return True
        except Exception as e:
            logger.error(f"重新加载规则失败: {e}")
            return False

def create_detector() -> ThreatDetector:
    """创建威胁检测器实例"""
    return ThreatDetector()