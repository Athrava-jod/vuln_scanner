# Use a lightweight Python base image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=10000

# Install system dependencies
# - nmap: for port scanning
# - libyara-dev, gcc, libc-dev: for yara-python compilation if needed
# - libmagic1: common dependency for file type detection
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libyara-dev \
    gcc \
    libc-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Create directories for persistence (if not using disk, these stay in container)
RUN mkdir -p static/reports instance

# Expose the port Flask runs on
EXPOSE 10000

# Start the application using Gunicorn
CMD gunicorn app:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120
