# Usage: source scripts/dev-env.sh
set -a
source "$(dirname "${BASH_SOURCE[0]}")/../deploy/.env"
set +a
export DATABASE_URL="postgresql://$POSTGRES_USER:$POSTGRES_PASSWORD@127.0.0.1:5432/$POSTGRES_DB"
echo "DATABASE_URL is set for this terminal"
