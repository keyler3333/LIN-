FROM python:3.10-slim
RUN apt-get update && apt-get install -y default-jre-headless && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY deobf-api/ /app/
RUN pip install -r requirements.txt
ADD https://github.com/HansWessels/unluac/releases/download/v2023.10.24/unluac.jar /opt/unluac.jar
CMD ["python", "api.py"]
