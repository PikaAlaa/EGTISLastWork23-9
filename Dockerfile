FROM python:3.12-slim
WORKDIR /app
COPY requirements-runtime.txt requirements-models.txt ./
ARG INCLUDE_TENSORFLOW=false
RUN if [ "$INCLUDE_TENSORFLOW" = "true" ]; then pip install --no-cache-dir -r requirements-models.txt; else pip install --no-cache-dir -r requirements-runtime.txt; fi
COPY backend ./backend
COPY ml/models ./ml/models
COPY ml/data/tokenizer.pkl ./ml/data/tokenizer.pkl
COPY data/scripts ./data/scripts
COPY scripts ./scripts
COPY alembic.ini ./
COPY .env.example ./
ENV PYTHONPATH=/app/backend
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--no-access-log"]
