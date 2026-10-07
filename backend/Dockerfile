FROM python:3.12-slim
RUN useradd --create-home --uid 10001 app
WORKDIR /srv
COPY backend/requirements.txt .
COPY shared/shield_common /tmp/shield_common
RUN pip install --no-cache-dir -r requirements.txt /tmp/shield_common && rm -rf /tmp/shield_common
COPY backend/app ./app
COPY backend/alembic ./alembic
COPY backend/alembic.ini .
USER app
# The API port is never published; only Caddy can reach it, so trusting its forwarded headers is safe.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--proxy-headers", "--forwarded-allow-ips", "*"]
