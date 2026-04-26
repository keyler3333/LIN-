FROM python:3.11-slim
RUN apt-get update && apt-get install -y lua5.1 && rm -rf /var/lib/apt/lists/*
RUN which lua5.1 && lua5.1 -v
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY api.py .
RUN python -c "import subprocess; print(subprocess.run(['lua5.1', '-v'], capture_output=True).stdout.decode())"
ENV LUA_BIN=/usr/bin/lua5.1
ENV PATH="/usr/bin:$PATH"
CMD ["python", "api.py"]
