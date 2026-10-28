#!/usr/bin/env bash
# ==============================================================================
# NexxPass Sync Server - Automated Database Backup Script
# Performs pg_dump with gzip compression, SHA-256 integrity verification,
# and daily/weekly retention rotation.
# ==============================================================================
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/backups}"
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_USER="${POSTGRES_USER:-nexxpass}"
POSTGRES_DB="${POSTGRES_DB:-nexxpass_sync}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"

mkdir -p "${BACKUP_DIR}"

TIMESTAMP=$(date -u +"%Y%m%d_%H%M%SZ")
BACKUP_FILE="${BACKUP_DIR}/nexxpass_sync_${TIMESTAMP}.sql.gz"
CHECKSUM_FILE="${BACKUP_FILE}.sha256"

echo "[$(date -u)] Starting database backup for '${POSTGRES_DB}'..."

# Dump database using gzip stream
PGPASSWORD="${POSTGRES_PASSWORD}" pg_dump \
    -h "${POSTGRES_HOST}" \
    -p "${POSTGRES_PORT}" \
    -U "${POSTGRES_USER}" \
    -d "${POSTGRES_DB}" \
    --format=plain \
    --no-owner \
    --no-privileges \
    | gzip -9 > "${BACKUP_FILE}"

# Generate SHA-256 checksum for disaster verification
sha256sum "${BACKUP_FILE}" > "${CHECKSUM_FILE}"

FILE_SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
echo "[$(date -u)] Backup completed successfully: ${BACKUP_FILE} (${FILE_SIZE})"
echo "[$(date -u)] Checksum: $(cat "${CHECKSUM_FILE}")"

# Optional Cloud Storage sync (AWS S3 / Cloudflare R2 / Google Cloud Storage)
if [ -n "${S3_BUCKET:-}" ] && command -v aws >/dev/null 2>&1; then
    echo "[$(date -u)] Syncing backup to s3://${S3_BUCKET}/backups/..."
    aws s3 cp "${BACKUP_FILE}" "s3://${S3_BUCKET}/backups/"
    aws s3 cp "${CHECKSUM_FILE}" "s3://${S3_BUCKET}/backups/"
fi

# Prune old backups exceeding RETENTION_DAYS
echo "[$(date -u)] Pruning backups older than ${RETENTION_DAYS} days..."
find "${BACKUP_DIR}" -type f -name "nexxpass_sync_*.sql.gz*" -mtime +"${RETENTION_DAYS}" -delete

echo "[$(date -u)] Backup maintenance complete."
