FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y python3 python3-pip python2 && apt clean

WORKDIR /app

# Optimize build cache: install dependencies before copying app source
COPY requirements.txt /app/
RUN pip3 install -r requirements.txt

COPY . /app

EXPOSE 8010

CMD bash -c "bash install_requests.sh && python3 androguard_server.py"