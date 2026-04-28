FROM python:3.11-slim
RUN apt-get update && apt-get install -y lua5.1 curl unzip && rm -rf /var/lib/apt/lists/*
RUN curl -L -o /tmp/lune.zip https://github.com/lune-org/lune/releases/latest/download/lune-x86_64-unknown-linux-musl.zip && unzip /tmp/lune.zip -d /usr/local/bin/ && chmod +x /usr/local/bin/lune && rm /tmp/lune.zip || echo "Lune install failed - emulator will be unavailable"
RUN lua5.1 -v
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "api.py"]
