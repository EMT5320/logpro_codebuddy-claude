@echo off
echo ========================================
echo 日志风险检测与自动修复系统
echo ========================================

REM 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo 错误: 未找到Python，请先安装Python 3.8+
    pause
    exit /b 1
)

REM 检查必要的包
echo 检查依赖包...
python -c "import numpy, pandas, sklearn, yaml, fastapi, uvicorn" >nul 2>&1
if errorlevel 1 (
    echo 安装依赖包...
    pip install numpy pandas scikit-learn pyyaml fastapi uvicorn
    if errorlevel 1 (
        echo 错误: 依赖包安装失败
        pause
        exit /b 1
    )
)

REM 创建必要的目录
if not exist "samples" mkdir samples
if not exist "out" mkdir out

echo.
echo ========================================
echo 1. 生成样本数据
echo ========================================
python samples/generator.py --lines 1000 --seed 42 --output mixed.log
if errorlevel 1 (
    echo 错误: 样本生成失败
    pause
    exit /b 1
)

echo.
echo ========================================
echo 2. 运行威胁检测分析
echo ========================================
python -m src.main analyze --file samples/mixed.log --tenant demo --mode balanced
if errorlevel 1 (
    echo 错误: 威胁检测失败
    pause
    exit /b 1
)

echo.
echo ========================================
echo 3. 运行系统评估
echo ========================================
python grader.py --file samples/mixed.log --output evaluation_results.json
if errorlevel 1 (
    echo 错误: 系统评估失败
    pause
    exit /b 1
)

echo.
echo ========================================
echo 4. 启动REST API服务 (可选)
echo ========================================
echo 是否启动API服务? (y/N)
set /p choice=
if /i "%choice%"=="y" (
    echo 启动API服务在 http://localhost:8000
    echo 按 Ctrl+C 停止服务
    python -m src.api
)

echo.
echo ========================================
echo 运行完成！
echo ========================================
echo 检查以下文件:
echo   - out/signals.jsonl    (威胁信号)
echo   - out/actions.jsonl    (执行动作)
echo   - out/metrics.json     (性能指标)
echo   - evaluation_results.json (评估结果)
echo ========================================
pause