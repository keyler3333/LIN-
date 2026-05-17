FROM python:3.10-slim

RUN apt-get update && apt-get install -y default-jre-headless lua5.1 curl && rm -rf /var/lib/apt/lists/*

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y \
    && . "$HOME/.cargo/env" \
    && cargo install lune --version 0.8.6 \
    && ln -s $HOME/.cargo/bin/lune /usr/local/bin/lune

RUN lune --version

WORKDIR /app
COPY deobf-api/ /app/
RUN pip install -r requirements.txt

ADD https://github.com/HansWessels/unluac/releases/download/v2023.10.24/unluac.jar /opt/unluac.jar
ENV UNLUAC_PATH=/opt/unluac.jar

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "api:app"]
