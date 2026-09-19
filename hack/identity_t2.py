#!/usr/bin/env python3
"""Embedded authority with only the MDM-owned PostgreSQL fixture; not product T3."""
from t2 import main
if __name__ == '__main__':
    main(identity_only=True)
