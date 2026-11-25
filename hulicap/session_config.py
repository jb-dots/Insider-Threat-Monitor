"""Session and Idle Timeout Configuration for HuliCAP."""

import os

# Centralized configuration with environment variable overrides
IDLE_WARN_SECONDS = int(os.environ.get("IDLE_WARN_SECONDS", "600"))      # Default: 10 minutes (600s)
IDLE_LOGOUT_SECONDS = int(os.environ.get("IDLE_LOGOUT_SECONDS", "900"))  # Default: 15 minutes (900s)
SESSION_LIFETIME_HOURS = int(os.environ.get("SESSION_LIFETIME_HOURS", "8"))  # Default: 8 hours
COOKIE_NAME = "hulicap_session"

