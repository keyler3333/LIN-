FROM python:3.11-slim
RUN apt-get update && apt-get install -y lua5.1 liblua5.1-0-dev gcc && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "api.py"]
