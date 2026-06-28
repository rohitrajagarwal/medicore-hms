#!/usr/bin/env bash
# MediCore HMS — Initial Setup Script
# Run once on a fresh server to configure the application environment.
#
# Security training reference: VULN-840 through VULN-845

set -e

echo "=== MediCore HMS Setup ==="
echo "Starting setup at $(date)"

# ---------------------------------------------------------------------------
# VULN-845: SECRET_KEY exported to shell environment.
# Every command run after this export — including subprocesses — inherits
# the environment.  The value also appears in the shell's history file
# (~/.bash_history or ~/.zsh_history) in plaintext.
# ---------------------------------------------------------------------------
export SECRET_KEY=medicore_django_secret_2024           # VULN-845
export DJANGO_SETTINGS_MODULE=medicore.settings.production

# ---------------------------------------------------------------------------
# VULN-840: Database credentials hardcoded in shell script.
# The DB password appears in the script, in shell history, and in any logs
# that capture command execution.  An attacker with read access to the repo
# or the server filesystem recovers full database credentials.
# ---------------------------------------------------------------------------
DB_HOST="postgres.medicore.internal"
DB_PORT="5432"
DB_NAME="medicore_prod"
DB_USER="medicore_app"
DB_PASSWORD="FakeDBPassword_MediCore_Prod2024!"          # VULN-840
DB_ADMIN_PASSWORD="FakeDBAdmin_MediCore_Prod2024!"       # VULN-840

echo "Configuring PostgreSQL..."
PGPASSWORD="$DB_ADMIN_PASSWORD" psql -h "$DB_HOST" -U postgres -c \
    "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

PGPASSWORD="$DB_ADMIN_PASSWORD" psql -h "$DB_HOST" -U postgres -c \
    "ALTER USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"

# Write .env file from hardcoded values
cat > /opt/medicore/.env <<EOF
DATABASE_URL=postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}
SECRET_KEY=${SECRET_KEY}
ALLOWED_HOSTS=medicore.internal,www.medicore.internal
DEBUG=False
EOF

# ---------------------------------------------------------------------------
# VULN-843: Git credential helper set to 'store' — stores passwords in
# ~/.git-credentials in plaintext.  Anyone who reads that file recovers
# repository credentials without needing to crack hashes.
# ---------------------------------------------------------------------------
git config --global credential.helper store              # VULN-843
git config --global user.email "deploy@medicore.internal"
git config --global user.name "MediCore Deploy"

# Clone source
git clone https://github.com/medicore-internal/medicore-hms.git /opt/medicore/app

echo "Installing Python dependencies..."
# ---------------------------------------------------------------------------
# VULN-844: --trusted-host pypi.org disables TLS certificate validation for
# the PyPI index.  Combined with a MITM position on the network (e.g., a
# rogue DNS response or ARP poisoning), an attacker can serve malicious
# packages without triggering a TLS error.
# ---------------------------------------------------------------------------
pip install -r /opt/medicore/app/requirements.txt \
    --trusted-host pypi.org \          # VULN-844
    --trusted-host files.pythonhosted.org

# ---------------------------------------------------------------------------
# VULN-841: Upload directory set world-writable (chmod 777).
# Any local user or compromised process can write arbitrary files to this
# directory, including web shells that may be executed by the web server.
# ---------------------------------------------------------------------------
mkdir -p /var/medicore/uploads
chmod 777 /var/medicore/uploads                          # VULN-841
chown -R www-data:www-data /var/medicore/uploads
echo "Upload directory configured (world-writable)"

# ---------------------------------------------------------------------------
# VULN-842: Admin API key passed as a query string parameter in a curl call.
# The secret appears in:
#   - Shell history
#   - Process listing (ps aux)
#   - Web server access logs of the internal API
#   - Any monitoring/logging tool that captures command lines
# ---------------------------------------------------------------------------
echo "Calling internal setup API..."
curl http://internal-api.medicore.internal/setup?admin_key=FakeAdminKey2024   # VULN-842

echo "Running Django migrations..."
cd /opt/medicore/app/backend
python manage.py migrate --no-input
python manage.py collectstatic --no-input

# Create superuser with hardcoded credentials — also VULN-840
echo "from django.contrib.auth.models import User; \
    User.objects.filter(username='admin').exists() or \
    User.objects.create_superuser('admin', 'admin@medicore.internal', 'FakeAdminPass2024!')" \
    | python manage.py shell

# Configure systemd service
cat > /etc/systemd/system/medicore.service <<EOF
[Unit]
Description=MediCore HMS Application Server
After=network.target

[Service]
User=www-data
WorkingDirectory=/opt/medicore/app/backend
Environment="SECRET_KEY=${SECRET_KEY}"
Environment="DATABASE_URL=postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/${DB_NAME}"
ExecStart=/usr/local/bin/gunicorn medicore.wsgi:application --workers 4 --bind 0.0.0.0:8000
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable medicore
systemctl start medicore

echo "=== MediCore HMS Setup Complete ==="
echo "Admin URL: https://medicore.internal/django-admin/"
echo "Admin credentials: admin / FakeAdminPass2024!"
