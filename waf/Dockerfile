FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    WAF_LISTEN_HOST=0.0.0.0 \
    WAF_LISTEN_PORT=8080 \
    WAF_UPSTREAM_BASE_URL=http://backend:5000

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY waf waf
COPY settings settings

EXPOSE 8080
CMD ["python", "-m", "waf.run"]
