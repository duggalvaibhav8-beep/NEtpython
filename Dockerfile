# Stage 1 - Builder
FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

COPY . .

# Stage 2 - Production
FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --from=builder /app /app

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]
