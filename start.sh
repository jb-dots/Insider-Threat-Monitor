#!/usr/bin/env bash
set -e
if [ -n "$SUPERADMIN_EMAIL" ] && [ -n "$SUPERADMIN_PASSWORD" ]; then
  python create_superadmin.py
fi
python collector.py &
exec streamlit run app.py --server.port "${PORT:-8501}" --server.address 0.0.0.0 --server.headless true
