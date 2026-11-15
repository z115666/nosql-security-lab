FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_MODULE=app.main_vulnerable:app

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app/ ./app/

# Usuario sin privilegios (mínimo privilegio también en el contenedor)
RUN useradd --system --uid 10001 --no-create-home appuser \
 && mkdir -p /app/logs && chown appuser /app/logs
USER appuser

EXPOSE 8000
# --proxy-headers: la IP real llega desde nginx (X-Forwarded-For) para el rate limit
CMD ["sh", "-c", "exec uvicorn ${APP_MODULE} --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'"]
