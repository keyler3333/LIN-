FROM python:3.11-slim
RUN apt-get update && apt-get install -y lua5.1 luajit liblua5.1-0-dev gcc curl unzip && rm -rf /var/lib/apt/lists/*
RUN curl -L -o /usr/local/bin/lune https://github.com/lune-org/lune/releases/latest/download/lune-ubuntu-latest && chmod +x /usr/local/bin/lune
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "api.py"]
