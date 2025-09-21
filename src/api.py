"""
REST API模块
提供HTTP接口用于日志分析和系统管理
"""

import json
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging

try:
    from fastapi import FastAPI, HTTPException, UploadFile, File, Form
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    # 如果FastAPI不可用，使用Flask作为备选
    try:
        from flask import Flask, request, jsonify
        FLASK_AVAILABLE = True
        FASTAPI_AVAILABLE = False
    except ImportError:
        FLASK_AVAILABLE = False
        FASTAPI_AVAILABLE = False

from .config import get_config, reload_config
from .main import LogAnalyzer

logger = logging.getLogger(__name__)

# 请求模型
if FASTAPI_AVAILABLE:
    class AnalyzeTextRequest(BaseModel):
        text: str
        tenant: str = "default"
        no_ml: bool = False
        
    class TrainRequest(BaseModel):
        tenant: str = "default"

class APIServer:
    """API服务器"""
    
    def __init__(self):
        self.config = get_config()
        self.analyzer = LogAnalyzer()
        
        if FASTAPI_AVAILABLE:
            self.app = self._create_fastapi_app()
        elif FLASK_AVAILABLE:
            self.app = self._create_flask_app()
        else:
            raise RuntimeError("需要安装 FastAPI 或 Flask")
            
    def _create_fastapi_app(self) -> FastAPI:
        """创建FastAPI应用"""
        app = FastAPI(
            title="日志风险检测与自动修复系统",
            description="生产级日志安全分析API",
            version="1.0.0"
        )
        
        @app.get("/health")
        async def health_check():
            """健康检查"""
            return {"status": "healthy", "timestamp": "2025-09-21T12:00:00Z"}
            
        @app.post("/analyze/text")
        async def analyze_text(request: AnalyzeTextRequest):
            """分析文本内容"""
            try:
                result = self.analyzer.analyze_text(
                    request.text, 
                    request.tenant, 
                    request.no_ml
                )
                return result
            except Exception as e:
                logger.error(f"文本分析失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
                
        @app.post("/analyze/file")
        async def analyze_file(
            file: UploadFile = File(...),
            tenant: str = Form("default"),
            no_ml: bool = Form(False)
        ):
            """分析上传的文件"""
            try:
                # 保存临时文件
                with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp_file:
                    content = await file.read()
                    tmp_file.write(content)
                    tmp_path = tmp_file.name
                    
                try:
                    result = self.analyzer.analyze_file(tmp_path, tenant, no_ml=no_ml)
                    return result
                finally:
                    # 清理临时文件
                    Path(tmp_path).unlink(missing_ok=True)
                    
            except Exception as e:
                logger.error(f"文件分析失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
                
        @app.post("/train")
        async def train_model(
            file: UploadFile = File(...),
            tenant: str = Form("default")
        ):
            """训练机器学习模型"""
            try:
                # 保存临时文件
                with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp_file:
                    content = await file.read()
                    tmp_file.write(content)
                    tmp_path = tmp_file.name
                    
                try:
                    result = self.analyzer.train_model(tmp_path, tenant)
                    return result
                finally:
                    # 清理临时文件
                    Path(tmp_path).unlink(missing_ok=True)
                    
            except Exception as e:
                logger.error(f"模型训练失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
                
        @app.post("/rules/reload")
        async def reload_rules():
            """重新加载规则"""
            try:
                success = reload_config()
                if success:
                    # 重新初始化检测器
                    self.analyzer.detector.reload_rules()
                    return {"success": True, "message": "规则重新加载成功"}
                else:
                    return {"success": False, "message": "规则重新加载失败"}
            except Exception as e:
                logger.error(f"重新加载规则失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
                
        @app.get("/metrics")
        async def get_metrics():
            """获取系统指标"""
            try:
                # 读取最新的指标文件
                metrics_path = Path("out/metrics.json")
                if metrics_path.exists():
                    with open(metrics_path, 'r', encoding='utf-8') as f:
                        metrics = json.load(f)
                else:
                    metrics = {"error": "指标文件不存在"}
                    
                # 添加关联器统计
                correlator_stats = self.analyzer.correlator.get_statistics()
                metrics.update(correlator_stats)
                
                return metrics
            except Exception as e:
                logger.error(f"获取指标失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
                
        @app.get("/actions")
        async def get_actions(limit: int = 100):
            """获取最近的动作记录"""
            try:
                actions = self.analyzer.action_bus.get_recent_actions(limit)
                return {"actions": actions, "count": len(actions)}
            except Exception as e:
                logger.error(f"获取动作记录失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
                
        return app
        
    def _create_flask_app(self):
        """创建Flask应用（备选方案）"""
        app = Flask(__name__)
        
        @app.route('/health', methods=['GET'])
        def health_check():
            return jsonify({"status": "healthy", "timestamp": "2025-09-21T12:00:00Z"})
            
        @app.route('/analyze/text', methods=['POST'])
        def analyze_text():
            try:
                data = request.get_json()
                result = self.analyzer.analyze_text(
                    data['text'], 
                    data.get('tenant', 'default'), 
                    data.get('no_ml', False)
                )
                return jsonify(result)
            except Exception as e:
                logger.error(f"文本分析失败: {e}")
                return jsonify({"error": str(e)}), 500
                
        @app.route('/metrics', methods=['GET'])
        def get_metrics():
            try:
                metrics_path = Path("out/metrics.json")
                if metrics_path.exists():
                    with open(metrics_path, 'r', encoding='utf-8') as f:
                        metrics = json.load(f)
                else:
                    metrics = {"error": "指标文件不存在"}
                return jsonify(metrics)
            except Exception as e:
                logger.error(f"获取指标失败: {e}")
                return jsonify({"error": str(e)}), 500
                
        return app
        
    def run(self, host: str = "0.0.0.0", port: int = 8080, workers: int = 1):
        """运行API服务器"""
        if FASTAPI_AVAILABLE:
            uvicorn.run(
                self.app,
                host=host,
                port=port,
                workers=workers,
                log_level="info"
            )
        elif FLASK_AVAILABLE:
            self.app.run(host=host, port=port, debug=False)
        else:
            raise RuntimeError("无可用的Web框架")

def main():
    """启动API服务器"""
    config = get_config()
    
    server = APIServer()
    
    host = config.get("api.host", "0.0.0.0")
    port = config.get("api.port", 8080)
    workers = config.get("api.workers", 1)
    
    logger.info(f"启动API服务器: http://{host}:{port}")
    
    try:
        server.run(host, port, workers)
    except KeyboardInterrupt:
        logger.info("API服务器已停止")
    except Exception as e:
        logger.error(f"API服务器启动失败: {e}")

if __name__ == '__main__':
    main()