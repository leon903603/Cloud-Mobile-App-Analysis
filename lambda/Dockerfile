# Lambda container image for android-static.
# Extends the original Ubuntu-based analysis env (keeps python2 + androguard)
# and adds the AWS Lambda Runtime Interface Client so it runs as a Lambda.
#
# Build from the REPO ROOT (context must include androguard_server.py,
# maldroid_main.py, the data JSONs, tools/, etc.):
#     docker build -f lambda/Dockerfile -t android-static-lambda .
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
        python3 python3-pip python3-dev \
        python2 curl \
        build-essential libcurl4-openssl-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /var/task
COPY . /var/task

# python3 analysis deps + Lambda runtime client + AWS SDK
RUN pip3 install --no-cache-dir -r requirements.txt \
    && pip3 install --no-cache-dir -r lambda/requirements-lambda.txt

# python2 'requests' for maldroid_main.py's localhost self-calls
RUN curl -sS https://bootstrap.pypa.io/pip/2.7/get-pip.py | python2 \
    && pip2 install --no-cache-dir requests==2.7.0 \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Handler modules live in lambda/; put it on the path so awslambdaric can
# resolve "worker_handler.handler" / "api_handler.handler" as top-level modules.
# (The directory is named "lambda" on disk but is never imported as a package.)
ENV PYTHONPATH=/var/task:/var/task/lambda

ENTRYPOINT ["/usr/bin/python3", "-m", "awslambdaric"]
# Overridden per function: api function uses "api_handler.handler".
CMD ["worker_handler.handler"]
