# ============================================================
# D-PHISH — Hugging Face Spaces Dockerfile
# Free tier: 2 vCPU, 16 GB RAM — plenty for scikit-learn model.
# ============================================================
FROM python:3.11-slim

# System deps required by lxml, psycopg2, whois, dnspython
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libxml2-dev \
        libxslt1-dev \
        libpq-dev \
        whois \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Hugging Face Spaces injects PORT=7860 automatically.
ENV PORT=7860
ENV FLASK_DEBUG=false
ENV PYTHONUNBUFFERED=1
EXPOSE 7860

# Run with gunicorn; 2 workers fit comfortably in 16GB RAM.
# --timeout 120 allows slow URL lookups (whois, DNS) to complete.
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:7860", "--timeout", "120", "app:app"]
