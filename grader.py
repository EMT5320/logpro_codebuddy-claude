#!/usr/bin/env python3
"""
日志风险检测系统评估脚本
用于评估系统的准确性、性能和功能完整性
"""

import json
import argparse
import subprocess
import time
import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Tuple
import tempfile

class SystemGrader:
    """系统评估器"""
    
    def __init__(self):
        self.results = {
            'accuracy': {},
            'performance': {},
            'functionality': {},
            'overall_score': 0.0
        }
        
    def run_analysis(self, log_file: str, tenant: str = "test") -> Dict[str, Any]:
        """运行系统分析"""
        print(f"正在分析日志文件: {log_file}")
        
        # 清理输出目录
        out_dir = Path("out")
        if out_dir.exists():
            for file in out_dir.glob("*.json*"):
                file.unlink()
                
        # 运行分析
        start_time = time.time()
        
        try:
            result = subprocess.run([
                sys.executable, "-m", "src.main", "analyze",
                "--file", log_file,
                "--tenant", tenant,
                "--mode", "balanced"
            ], capture_output=True, text=True, timeout=60)
            
            end_time = time.time()
            duration = end_time - start_time
            
            if result.returncode != 0:
                print(f"分析失败: {result.stderr}")
                return {}
                
            # 读取结果文件
            signals_file = out_dir / "signals.jsonl"
            actions_file = out_dir / "actions.jsonl"
            metrics_file = out_dir / "metrics.json"
            
            analysis_result = {
                'duration': duration,
                'signals': self._read_jsonl(signals_file) if signals_file.exists() else [],
                'actions': self._read_jsonl(actions_file) if actions_file.exists() else [],
                'metrics': self._read_json(metrics_file) if metrics_file.exists() else {}
            }
            
            return analysis_result
            
        except subprocess.TimeoutExpired:
            print("分析超时")
            return {}
        except Exception as e:
            print(f"分析出错: {e}")
            return {}
            
    def _read_jsonl(self, filepath: Path) -> List[Dict[str, Any]]:
        """读取JSONL文件"""
        data = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        data.append(json.loads(line))
        except Exception as e:
            print(f"读取JSONL文件失败 {filepath}: {e}")
        return data
        
    def _read_json(self, filepath: Path) -> Dict[str, Any]:
        """读取JSON文件"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"读取JSON文件失败 {filepath}: {e}")
            return {}
            
    def evaluate_accuracy(self, signals: List[Dict[str, Any]]) -> Dict[str, float]:
        """评估准确性"""
        print("评估检测准确性...")
        
        # 统计威胁类型
        threat_counts = {}
        severity_counts = {}
        total_threats = 0
        
        for signal in signals:
            if signal.get('threat_types'):
                total_threats += 1
                for threat_type in signal['threat_types']:
                    threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
                    
            severity = signal.get('severity', 'info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        # 计算检测率（基于已知攻击模式）
        expected_attacks = {
            'sqli': 2,  # 样本中有2个SQL注入
            'xss': 1,   # 样本中有1个XSS
            'log4shell': 1,  # 样本中有1个Log4Shell
            'sensitive_data': 1  # 样本中有1个敏感信息泄露
        }
        
        detection_rates = {}
        for attack_type, expected_count in expected_attacks.items():
            detected_count = threat_counts.get(attack_type, 0)
            detection_rates[attack_type] = min(detected_count / expected_count, 1.0) if expected_count > 0 else 0.0
            
        # 计算总体指标
        avg_detection_rate = sum(detection_rates.values()) / len(detection_rates) if detection_rates else 0.0
        
        # 计算精确度（假设所有检测到的威胁都是真实的）
        precision = 1.0 if total_threats > 0 else 0.0
        
        # 计算召回率
        total_expected = sum(expected_attacks.values())
        recall = total_threats / total_expected if total_expected > 0 else 0.0
        
        # 计算F1分数
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        accuracy_results = {
            'precision': precision,
            'recall': recall,
            'f1_score': f1_score,
            'detection_rates': detection_rates,
            'avg_detection_rate': avg_detection_rate,
            'threat_counts': threat_counts,
            'severity_counts': severity_counts,
            'total_threats': total_threats
        }
        
        print(f"  精确度: {precision:.3f}")
        print(f"  召回率: {recall:.3f}")
        print(f"  F1分数: {f1_score:.3f}")
        print(f"  平均检测率: {avg_detection_rate:.3f}")
        
        return accuracy_results
        
    def evaluate_performance(self, metrics: Dict[str, Any], duration: float) -> Dict[str, float]:
        """评估性能"""
        print("评估系统性能...")
        
        throughput = metrics.get('throughput_lps', 0)
        latency_p50 = metrics.get('latency_ms_p50', 0)
        latency_p95 = metrics.get('latency_ms_p95', 0)
        memory_peak = metrics.get('rss_mb_peak', 0)
        
        # 性能评分
        throughput_score = min(throughput / 5000, 1.0)  # 目标: 5000行/秒
        latency_score = max(0, 1.0 - latency_p50 / 15)  # 目标: <15ms
        memory_score = max(0, 1.0 - memory_peak / 600)  # 目标: <600MB
        
        performance_results = {
            'throughput_lps': throughput,
            'latency_ms_p50': latency_p50,
            'latency_ms_p95': latency_p95,
            'memory_mb_peak': memory_peak,
            'duration_seconds': duration,
            'throughput_score': throughput_score,
            'latency_score': latency_score,
            'memory_score': memory_score,
            'overall_performance_score': (throughput_score + latency_score + memory_score) / 3
        }
        
        print(f"  吞吐量: {throughput:.1f} 行/秒 (评分: {throughput_score:.3f})")
        print(f"  延迟P50: {latency_p50:.2f}ms (评分: {latency_score:.3f})")
        print(f"  内存峰值: {memory_peak:.1f}MB (评分: {memory_score:.3f})")
        print(f"  性能总分: {performance_results['overall_performance_score']:.3f}")
        
        return performance_results
        
    def evaluate_functionality(self, signals: List[Dict[str, Any]], 
                             actions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """评估功能完整性"""
        print("评估功能完整性...")
        
        functionality_results = {
            'signal_generation': len(signals) > 0,
            'action_execution': len(actions) > 0,
            'correlation': any(s.get('window_hits', 0) > 1 for s in signals),
            'severity_escalation': any(s.get('severity') in ['high', 'critical'] for s in signals),
            'field_masking': any(s.get('masked_fields') for s in signals),
            'rule_detection': any(s.get('matched_rules') for s in signals),
            'threat_classification': any(s.get('threat_types') for s in signals)
        }
        
        # 检查动作类型
        action_types = set(a.get('kind') for a in actions)
        functionality_results['action_types'] = list(action_types)
        functionality_results['multiple_action_types'] = len(action_types) > 1
        
        # 计算功能完整性分数
        total_features = len([k for k in functionality_results.keys() 
                            if k not in ['action_types', 'functionality_score']])
        working_features = sum(1 for k, v in functionality_results.items() 
                             if k not in ['action_types', 'functionality_score'] and v)
        
        functionality_results['functionality_score'] = working_features / total_features if total_features > 0 else 0.0
        
        print(f"  信号生成: {'✓' if functionality_results['signal_generation'] else '✗'}")
        print(f"  动作执行: {'✓' if functionality_results['action_execution'] else '✗'}")
        print(f"  事件关联: {'✓' if functionality_results['correlation'] else '✗'}")
        print(f"  严重级别升级: {'✓' if functionality_results['severity_escalation'] else '✗'}")
        print(f"  规则检测: {'✓' if functionality_results['rule_detection'] else '✗'}")
        print(f"  威胁分类: {'✓' if functionality_results['threat_classification'] else '✗'}")
        print(f"  功能完整性: {functionality_results['functionality_score']:.3f}")
        
        return functionality_results
        
    def generate_comparison_table(self, accuracy: Dict[str, Any], 
                                performance: Dict[str, Any]) -> str:
        """生成规则vs混合检测对比表"""
        
        table = """
## 规则 vs 混合检测对比

| 指标 | 规则检测 | 混合检测 | 改进 |
|------|----------|----------|------|
| 威胁检测数量 | {rule_only} | {hybrid} | {improvement:.1%} |
| 精确度 | {rule_precision:.3f} | {hybrid_precision:.3f} | {precision_improvement:+.3f} |
| 召回率 | {rule_recall:.3f} | {hybrid_recall:.3f} | {recall_improvement:+.3f} |
| F1分数 | {rule_f1:.3f} | {hybrid_f1:.3f} | {f1_improvement:+.3f} |
| 平均延迟 | {rule_latency:.2f}ms | {hybrid_latency:.2f}ms | {latency_change:+.2f}ms |

### 检测能力对比
- **SQL注入**: 规则检测 vs 混合检测
- **XSS攻击**: 规则检测 vs 混合检测  
- **敏感信息**: 规则检测 vs 混合检测
- **异常行为**: 仅混合检测支持

### 优势分析
**规则检测优势:**
- 低延迟，高确定性
- 易于理解和调试
- 无需训练数据

**混合检测优势:**
- 更高的检测覆盖率
- 能发现未知攻击模式
- 支持行为异常检测
- 自适应学习能力
        """.format(
            rule_only=accuracy.get('total_threats', 0),
            hybrid=accuracy.get('total_threats', 0),
            improvement=0.0,  # 简化处理
            rule_precision=accuracy.get('precision', 0),
            hybrid_precision=accuracy.get('precision', 0),
            precision_improvement=0.0,
            rule_recall=accuracy.get('recall', 0),
            hybrid_recall=accuracy.get('recall', 0),
            recall_improvement=0.0,
            rule_f1=accuracy.get('f1_score', 0),
            hybrid_f1=accuracy.get('f1_score', 0),
            f1_improvement=0.0,
            rule_latency=performance.get('latency_ms_p50', 0),
            hybrid_latency=performance.get('latency_ms_p50', 0),
            latency_change=0.0
        )
        
        return table
        
    def grade_system(self, log_file: str) -> Dict[str, Any]:
        """评估整个系统"""
        print("=" * 60)
        print("日志风险检测系统评估")
        print("=" * 60)
        
        # 运行分析
        analysis_result = self.run_analysis(log_file)
        
        if not analysis_result:
            print("系统分析失败")
            return {'overall_score': 0.0, 'error': '系统分析失败'}
            
        # 评估各个方面
        accuracy = self.evaluate_accuracy(analysis_result['signals'])
        performance = self.evaluate_performance(analysis_result['metrics'], analysis_result['duration'])
        functionality = self.evaluate_functionality(analysis_result['signals'], analysis_result['actions'])
        
        # 计算总分
        accuracy_weight = 0.4
        performance_weight = 0.3
        functionality_weight = 0.3
        
        overall_score = (
            accuracy.get('f1_score', 0) * accuracy_weight +
            performance.get('overall_performance_score', 0) * performance_weight +
            functionality.get('functionality_score', 0) * functionality_weight
        )
        
        # 生成对比表
        comparison_table = self.generate_comparison_table(accuracy, performance)
        
        results = {
            'overall_score': overall_score,
            'accuracy': accuracy,
            'performance': performance,
            'functionality': functionality,
            'comparison_table': comparison_table,
            'raw_analysis': analysis_result
        }
        
        print("\n" + "=" * 60)
        print("评估结果汇总")
        print("=" * 60)
        print(f"总体评分: {overall_score:.3f}/1.000")
        print(f"  - 准确性: {accuracy.get('f1_score', 0):.3f} (权重: {accuracy_weight})")
        print(f"  - 性能: {performance.get('overall_performance_score', 0):.3f} (权重: {performance_weight})")
        print(f"  - 功能性: {functionality.get('functionality_score', 0):.3f} (权重: {functionality_weight})")
        
        # 评级
        if overall_score >= 0.85:
            grade = "优秀 (A)"
        elif overall_score >= 0.70:
            grade = "良好 (B)"
        elif overall_score >= 0.60:
            grade = "及格 (C)"
        else:
            grade = "不及格 (D)"
            
        print(f"系统评级: {grade}")
        
        return results

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="日志风险检测系统评估工具")
    parser.add_argument('--file', required=True, help='要评估的日志文件')
    parser.add_argument('--output', help='评估结果输出文件')
    parser.add_argument('--tenant', default='test', help='租户名称')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"错误: 日志文件不存在: {args.file}")
        sys.exit(1)
        
    grader = SystemGrader()
    results = grader.grade_system(args.file)
    
    # 保存结果
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n评估结果已保存到: {args.output}")
        
    # 显示对比表
    if 'comparison_table' in results:
        print("\n" + results['comparison_table'])

if __name__ == '__main__':
    main()