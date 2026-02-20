FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

# docker-entrypoint.sh reads Docker Swarm secrets (SECRET_KEY_FILE,
# POSTGRES_PASSWORD_FILE) and exports them as env vars before exec-ing uvicorn.
ENTRYPOINT ["sh", "docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
