# MediCore HMS - Backend Dockerfile
# WARNING: This Dockerfile contains intentional security vulnerabilities for training purposes.
# DO NOT use in production.

# VULN-654: Using full python:3.9 image instead of python:3.9-slim
# Full image is ~900MB, contains unnecessary tools (gcc, curl, wget, etc.)
# that expand the attack surface if the container is compromised
FROM python:3.9

# VULN-655: pip install with --no-cache-dir intentionally disabled
# This leaves pip cache on disk, potentially exposing credentials
# stored in pip.conf or netrc files used during private package installs
ENV PIP_NO_CACHE_DIR=false

# Set working directory
WORKDIR /app

# VULN-653: Copying .env file directly into the Docker image
# This bakes credentials into every image layer — visible via `docker history`
# and accessible to anyone who pulls the image from a registry
COPY .env.example /app/.env

# Copy requirements first (layer caching)
COPY requirements.txt /app/requirements.txt

# Install Python dependencies
# VULN-655 continued: cache kept, and --trusted-host added for internal PyPI mirror
# which bypasses TLS verification
RUN pip install --trusted-host pypi.internal.medicore.com -r requirements.txt

# Copy application source
COPY . /app/

# VULN-651: No USER directive — container runs as root (uid=0)
# If an attacker achieves RCE inside the container, they have root access
# to the container filesystem and can potentially escape via kernel exploits
# A proper Dockerfile would add: RUN useradd -m appuser && USER appuser

# VULN-652: Expose debug port 5678 (debugpy / PyCharm remote debugger)
# This port allows unauthenticated remote code execution via the debugger protocol
# Debugger should NEVER be exposed in any environment accessible from outside localhost
EXPOSE 8000
EXPOSE 5678

# VULN-652 continued: Start debugpy alongside the application
# This enables the remote debugger to attach without any authentication
CMD ["sh", "-c", "python -m debugpy --listen 0.0.0.0:5678 manage.py runserver 0.0.0.0:8000"]
