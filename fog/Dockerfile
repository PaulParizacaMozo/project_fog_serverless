FROM python:3.11-slim

WORKDIR /app

# Install deps
COPY fog/requirements.txt /app/fog/requirements.txt
RUN pip install --no-cache-dir -r /app/fog/requirements.txt

# Copy fog code
COPY fog/app /app/app

# Copy shared contracts (imported via PYTHONPATH)
COPY shared/python /app/shared/python
ENV PYTHONPATH=/app/shared/python

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]

