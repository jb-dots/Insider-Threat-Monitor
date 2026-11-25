#!/usr/bin/env bash
set -e
if [ -n "$SUPERADMIN_EMAIL" ] && [ -n "$SUPERADMIN_PASSWORD" ]; then
  python -m hulicap.create_superadmin
fi
python -m hulicap.collector &
exec streamlit run app.py --server.port "${PORT:-8501}" --server.address 0.0.0.0 --server.headless true
