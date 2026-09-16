FROM python:3.11.8-slim

WORKDIR /app

# Optimize build cache: install dependencies before copying app source
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app

EXPOSE 5001
CMD ["python", "wrapper.py"]
