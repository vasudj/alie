FROM python:3.11-slim

# Non-root user for security
RUN addgroup --system app && adduser --system --group app

WORKDIR /app

# Install deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Make sure scripts package is importable
RUN touch scripts/__init__.py

# Change ownership
RUN chown -R app:app /app
USER app

EXPOSE 8000 9001 9002 9003 9004

# Default: run the gateway
CMD ["python", "-m", "uvicorn", "main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", "--access-log", "--log-level", "info"]
