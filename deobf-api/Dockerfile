FROM python:3.11-slim
RUN apt-get update && apt-get install -y lua5.1 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api.py .
CMD ["python", "api.py"]
