"""Formal SQL catalogs and command runtime admission, one read-only scenario."""
from command_catalog import capture

def execute(fixture):
    capture(fixture.owner.container(), 'check', fixture.database)
