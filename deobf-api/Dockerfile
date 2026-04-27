FROM python:3.11-slim
RUN apt-get update && apt-get install -y lua5.1 liblua5.1-0-dev gcc && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY hooks.c .
RUN gcc -shared -fPIC -o hooks.so hooks.c -I/usr/include/lua5.1
COPY api.py .
CMD ["python", "api.py"]
