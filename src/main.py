"""
主程序模块
提供CLI接口和核心处理流程
"""

import sys
import argparse
import time
import json
import gzip
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Iterator
import logging
import psutil
import threading

from .config import get_config, reload_config
from .parser import create_parser
from .normalizer import create_normalizer
from .detector import create_detector
from .correlator import create_correlator
from .responder import create_action_bus

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class LogAnalyzer:
    """日志分析器主类"""
    
    def __init__(self, seed: Optional[int] = None):
        self.config = get_config()
        
        # 设置随机种子
        if seed is not None:
            import random
            import numpy as np
            random.seed(seed)
            np.random.seed(seed)
            
        # 初始化组件
        self.parser = create_parser()
        self.normalizer = create_normalizer()
        self.detector = create_detector()
        self.correlator = create_correlator()
        self.action_bus = create_action_bus()
        
        # 统计信息
        self.stats = {
            'lines_processed': 0,
            'events_parsed': 0,
            'threats_detected': 0,
            'actions_executed': 0,
            'start_time': 0,
            'end_time': 0,
            'memory_peak_mb': 0,
            'rule_hits': 0,
            'ml_hits': 0,
            'suppressed': 0,
            'actions_failed': 0
        }
        
        # 输出文件
        self.signals_file = None
        self.actions_file = None
        
    def analyze_file(self, file_path: str, tenant: str = "default", 
                    mode: str = "balanced", no_ml: bool = False,
                    window: str = "60s") -> Dict[str, Any]:
        """分析日志文件"""
        
        logger.info(f"开始分析文件: {file_path}")
        
        # 初始化输出文件
        self._init_output_files()
        
        # 开始统计
        self.stats['start_time'] = time.time()
        process = psutil.Process()
        
        try:
            # 解析和处理日志
            for event in self.parser.parse_file(file_path, tenant):
                self._process_event(event, no_ml)
                
                # 更新内存峰值
                memory_mb = process.memory_info().rss / 1024 / 1024
                self.stats['memory_peak_mb'] = max(self.stats['memory_peak_mb'], memory_mb)
                
                # 每1000行输出一次进度
                if self.stats['lines_processed'] % 1000 == 0:
                    logger.info(f"已处理 {self.stats['lines_processed']} 行")
                    
        except KeyboardInterrupt:
            logger.info("用户中断分析")
        except Exception as e:
            logger.error(f"分析失败: {e}")
            raise
        finally:
            self.stats['end_time'] = time.time()
            self._close_output_files()
            
        # 生成指标文件
        self._write_metrics()
        
        return self._get_analysis_results()
        
    def analyze_stdin(self, tenant: str = "default", no_ml: bool = False) -> Dict[str, Any]:
        """从标准输入分析日志"""
        
        logger.info("从标准输入读取日志")
        
        # 初始化输出文件
        self._init_output_files()
        
        # 开始统计
        self.stats['start_time'] = time.time()
        process = psutil.Process()
        
        try:
            # 逐行读取标准输入
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                    
                # 解析单行
                event = self.parser.parse_line(line, tenant)
                if event:
                    self._process_event(event, no_ml)
                    
                # 更新内存峰值
                memory_mb = process.memory_info().rss / 1024 / 1024
                self.stats['memory_peak_mb'] = max(self.stats['memory_peak_mb'], memory_mb)
                
        except KeyboardInterrupt:
            logger.info("用户中断分析")
        except Exception as e:
            logger.error(f"分析失败: {e}")
            raise
        finally:
            self.stats['end_time'] = time.time()
            self._close_output_files()
            
        # 生成指标文件
        self._write_metrics()
        
        return self._get_analysis_results()
        
    def analyze_text(self, text: str, tenant: str = "default", 
                    no_ml: bool = False) -> Dict[str, Any]:
        """分析文本内容"""
        
        # 初始化输出文件
        self._init_output_files()
        
        # 开始统计
        self.stats['start_time'] = time.time()
        
        try:
            # 解析文本
            for event in self.parser.parse_text(text, tenant):
                self._process_event(event, no_ml)
                
        finally:
            self.stats['end_time'] = time.time()
            self._close_output_files()
            
        # 生成指标文件
        self._write_metrics()
        
        return self._get_analysis_results()
        
    def _process_event(self, event: Dict[str, Any], no_ml: bool = False) -> None:
        """处理单个事件"""
        self.stats['lines_processed'] += 1
        
        try:
            # 标准化
            normalized_event = self.normalizer.normalize(event)
            self.stats['events_parsed'] += 1
            
            # 威胁检测
            if no_ml:
                # 临时禁用ML
                original_ml_enabled = self.config.get("ml.enabled", True)
                self.config.set("ml.enabled", False)
                
            detection_result = self.detector.detect(normalized_event)
            
            if no_ml:
                # 恢复ML设置
                self.config.set("ml.enabled", original_ml_enabled)
                
            # 更新统计
            if detection_result['is_threat']:
                self.stats['threats_detected'] += 1
                
                if detection_result['matched_rules']:
                    self.stats['rule_hits'] += 1
                    
                if detection_result.get('ml_score', 0) > 0.7:
                    self.stats['ml_hits'] += 1
                    
            # 事件关联
            signal = self.correlator.correlate(detection_result, normalized_event)
            
            if signal:
                # 写入信号文件
                self._write_signal(signal)
                
                # 执行自动处置
                actions = self.action_bus.execute_actions(signal)
                
                for action in actions:
                    self._write_action(action)
                    
                    if action['status'] == 'executed':
                        self.stats['actions_executed'] += 1
                    elif action['status'] == 'failed':
                        self.stats['actions_failed'] += 1
                        
            else:
                self.stats['suppressed'] += 1
                
        except Exception as e:
            logger.error(f"处理事件失败: {e}")
            
    def _init_output_files(self) -> None:
        """初始化输出文件"""
        # 确保输出目录存在
        Path("out").mkdir(exist_ok=True)
        
        # 打开输出文件
        self.signals_file = open("out/signals.jsonl", "w", encoding="utf-8")
        self.actions_file = open("out/actions.jsonl", "w", encoding="utf-8")
        
    def _close_output_files(self) -> None:
        """关闭输出文件"""
        if self.signals_file:
            self.signals_file.close()
            
        if self.actions_file:
            self.actions_file.close()
            
    def _write_signal(self, signal: Dict[str, Any]) -> None:
        """写入信号到文件"""
        if self.signals_file:
            json.dump(signal, self.signals_file, ensure_ascii=False)
            self.signals_file.write('\n')
            self.signals_file.flush()
            
    def _write_action(self, action: Dict[str, Any]) -> None:
        """写入动作到文件"""
        if self.actions_file:
            json.dump(action, self.actions_file, ensure_ascii=False)
            self.actions_file.write('\n')
            self.actions_file.flush()
            
    def _write_metrics(self) -> None:
        """写入指标文件"""
        duration = self.stats['end_time'] - self.stats['start_time']
        
        metrics = {
            'throughput_lps': self.stats['lines_processed'] / max(duration, 0.001),
            'latency_ms_p50': (duration * 1000) / max(self.stats['lines_processed'], 1),
            'latency_ms_p95': (duration * 1000) / max(self.stats['lines_processed'], 1) * 1.5,
            'rss_mb_peak': self.stats['memory_peak_mb'],
            'rule_hits': self.stats['rule_hits'],
            'ml_hits': self.stats['ml_hits'],
            'suppressed': self.stats['suppressed'],
            'actions_executed': self.stats['actions_executed'],
            'actions_failed': self.stats['actions_failed'],
            'total_lines': self.stats['lines_processed'],
            'total_events': self.stats['events_parsed'],
            'total_threats': self.stats['threats_detected'],
            'duration_seconds': duration
        }
        
        with open("out/metrics.json", "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2, ensure_ascii=False)
            
    def _get_analysis_results(self) -> Dict[str, Any]:
        """获取分析结果"""
        duration = self.stats['end_time'] - self.stats['start_time']
        
        return {
            'success': True,
            'lines_processed': self.stats['lines_processed'],
            'events_parsed': self.stats['events_parsed'],
            'threats_detected': self.stats['threats_detected'],
            'actions_executed': self.stats['actions_executed'],
            'duration_seconds': duration,
            'throughput_lps': self.stats['lines_processed'] / max(duration, 0.001),
            'memory_peak_mb': self.stats['memory_peak_mb']
        }
        
    def train_model(self, training_file: str, tenant: str = "default") -> Dict[str, Any]:
        """训练机器学习模型"""
        logger.info(f"开始训练模型，使用文件: {training_file}")
        
        # 收集训练数据
        training_data = []
        labels = []
        
        for event in self.parser.parse_file(training_file, tenant):
            normalized_event = self.normalizer.normalize(event)
            training_data.append(normalized_event)
            
            # 简单的标签生成逻辑（实际应用中需要人工标注）
            # 这里基于规则检测结果生成标签
            detection_result = self.detector.detect(normalized_event)
            label = 1 if detection_result['is_threat'] else 0
            labels.append(label)
            
        # 训练模型
        return self.detector.train_ml_model(training_data, labels)

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="日志风险检测与自动修复系统")
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # analyze命令
    analyze_parser = subparsers.add_parser('analyze', help='分析日志')
    analyze_parser.add_argument('--file', type=str, help='日志文件路径')
    analyze_parser.add_argument('--stdin', action='store_true', help='从标准输入读取')
    analyze_parser.add_argument('--tenant', type=str, default='default', help='租户名称')
    analyze_parser.add_argument('--window', type=str, default='60s', help='关联窗口大小')
    analyze_parser.add_argument('--mode', type=str, default='balanced', 
                              choices=['fast', 'balanced', 'accurate'], help='检测模式')
    analyze_parser.add_argument('--no-ml', action='store_true', help='禁用机器学习')
    analyze_parser.add_argument('--seed', type=int, help='随机种子')
    
    # train命令
    train_parser = subparsers.add_parser('train', help='训练模型')
    train_parser.add_argument('--file', type=str, required=True, help='训练数据文件')
    train_parser.add_argument('--tenant', type=str, default='default', help='租户名称')
    
    # reload命令
    reload_parser = subparsers.add_parser('reload', help='重新加载配置')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
        
    try:
        if args.command == 'analyze':
            analyzer = LogAnalyzer(seed=args.seed)
            
            if args.stdin:
                result = analyzer.analyze_stdin(args.tenant, args.no_ml)
            elif args.file:
                result = analyzer.analyze_file(args.file, args.tenant, args.mode, args.no_ml, args.window)
            else:
                print("错误: 必须指定 --file 或 --stdin")
                return
                
            print(f"分析完成:")
            print(f"  处理行数: {result['lines_processed']}")
            print(f"  解析事件: {result['events_parsed']}")
            print(f"  检测威胁: {result['threats_detected']}")
            print(f"  执行动作: {result['actions_executed']}")
            print(f"  处理时间: {result['duration_seconds']:.2f}秒")
            print(f"  吞吐量: {result['throughput_lps']:.0f}行/秒")
            print(f"  内存峰值: {result['memory_peak_mb']:.1f}MB")
            
        elif args.command == 'train':
            analyzer = LogAnalyzer()
            result = analyzer.train_model(args.file, args.tenant)
            
            if result['success']:
                print("模型训练完成:")
                print(f"  训练样本: {result['train_samples']}")
                print(f"  测试样本: {result['test_samples']}")
                print(f"  精确率: {result['precision']:.3f}")
                print(f"  召回率: {result['recall']:.3f}")
                print(f"  F1分数: {result['f1_score']:.3f}")
            else:
                print(f"模型训练失败: {result['error']}")
                
        elif args.command == 'reload':
            if reload_config():
                print("配置重新加载成功")
            else:
                print("配置重新加载失败")
                
    except Exception as e:
        logger.error(f"执行失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()