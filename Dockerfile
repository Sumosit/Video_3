FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libpq-dev && \
    rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt ./
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . /app

# Collect static files if applicable (uncomment if needed)
# RUN python manage.py collectstatic --noinput

# Expose port
EXPOSE 8000

# Run Gunicorn with Uvicorn workers, optimized for performance and security
CMD ["gunicorn", "main:app", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "--limit-request-line", "8190", "--access-logfile", "-", "--error-logfile", "-", "--keep-alive", "30"]