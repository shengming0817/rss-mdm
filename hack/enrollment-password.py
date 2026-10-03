#!/usr/bin/env python3
"""Generate and retain this password before POST /api/v1/enrollments or /resume."""
import secrets
print(secrets.token_urlsafe(32))
