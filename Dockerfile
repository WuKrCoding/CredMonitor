FROM python:3.11-slim

WORKDIR /app

# 复制依赖文件并安装 Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY . .

# 创建数据目录
RUN mkdir -p /data

# 设置环境变量
ENV DATABASE_PATH=/data/credmonitor.db
ENV HOST=0.0.0.0
ENV PORT=5000
ENV DEBUG=False

# 暴露端口
EXPOSE 5000

# 启动命令
CMD ["python", "app.py"]
