FROM python:3.11-slim

WORKDIR /app

COPY cloud/app/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# app
COPY cloud/app /app

# shared contracts (para validación)
COPY shared/python /app/shared/python
ENV PYTHONPATH=/app/shared/python

# web dashboard (local)
COPY cloud/web /app/web

EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
