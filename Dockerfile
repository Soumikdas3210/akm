# Image shared by every verifier container. Built once:  docker compose build
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY akm/ akm/
# The run directory is NOT baked in: each service mounts only its allowed files at /data
ENTRYPOINT ["python", "-m"]
