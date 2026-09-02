FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /var/task

RUN apt-get update && apt-get install -y \
    build-essential \
    libcurl4-openssl-dev \
    libfreetype6-dev \
    libjpeg-dev \
    zlib1g-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY app/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir awslambdaric boto3

COPY app/ ./
COPY lambda/handler.py ./

ENTRYPOINT ["/usr/local/bin/python", "-m", "awslambdaric"]
CMD ["handler.handler"]
