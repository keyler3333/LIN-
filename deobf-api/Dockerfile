FROM python:3.11-slim
RUN apt-get update && apt-get install -y lua5.1 curl && rm -rf /var/lib/apt/lists/*
RUN curl -L -o /usr/local/bin/lune \
    https://github.com/lune-org/lune/releases/latest/download/lune-x86_64-unknown-linux-musl \
    && chmod +x /usr/local/bin/lune \
    || echo "Lune install failed - emulator path unavailable"
RUN lua5.1 -v
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "api.py"]
