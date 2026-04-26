FROM python:3.11-slim
RUN apt-get update && apt-get install -y lua5.1 nodejs npm git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN git clone https://github.com/nicowillis/Lua-Deobfuscator /app/Lua-Deobfuscator || true
RUN cd /app/Lua-Deobfuscator && npm install || true
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY api.py .
CMD ["python", "api.py"]
