# Dockerfile for FastAPI WAF Application
# Using slim variant with build tools already included (avoid large apt-get installs)
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
# --no-cache-dir keeps image smaller
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY main.py .
COPY distilbert_http_mlm_epoch22/ ./distilbert_http_mlm_epoch22/
COPY scaler.pkl .
COPY iforest.pkl .
COPY train_features_dvwa_fix_seed.npy .

# Expose port
EXPOSE 8001

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV REDIS_URL=redis://redis:6379
ENV MONGO_URI=mongodb://mongodb:27017/waf_db

# Health check
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8001/health')" || exit 1

# Run application
CMD ["python", "main.py"]
