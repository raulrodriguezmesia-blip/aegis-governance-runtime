"""Aegis Demo Tamper Utility — V1.6.

Intentionally NOT part of the runtime. Used only by demos and attack tests
to simulate DB tampering that bypasses the SQLite append-only triggers.
"""
import sqlite3


def tamper_event_verdict(db_path: str, seq: int, new_verdict: str = "TAMPERED") -> None:
    """Tamper with an event verdict (demo only). Bypasses trigger."""
    conn = sqlite3.connect(db_path)
    conn.execute("DROP TRIGGER IF EXISTS prevent_update")
    conn.execute("UPDATE events SET verdict=? WHERE seq=?", (new_verdict, seq))
    conn.commit()
    conn.execute("""CREATE TRIGGER IF NOT EXISTS prevent_update
        BEFORE UPDATE ON events
        BEGIN
            SELECT RAISE(ABORT, 'UPDATE on events table is not allowed');
        END;""")
    conn.commit()
    conn.close()


def tamper_event_payload(db_path: str, seq: int, new_payload: str) -> None:
    """Tamper with an event payload (demo only)."""
    conn = sqlite3.connect(db_path)
    conn.execute("DROP TRIGGER IF EXISTS prevent_update")
    conn.execute("UPDATE events SET payload=? WHERE seq=?", (new_payload, seq))
    conn.commit()
    conn.execute("""CREATE TRIGGER IF NOT EXISTS prevent_update
        BEFORE UPDATE ON events
        BEGIN
            SELECT RAISE(ABORT, 'UPDATE on events table is not allowed');
        END;""")
    conn.commit()
    conn.close()


def truncate_tail(db_path: str, keep: int) -> None:
    """Truncate the tail of the ledger (demo only)."""
    conn = sqlite3.connect(db_path)
    conn.execute("DROP TRIGGER IF EXISTS prevent_delete")
    conn.execute("DELETE FROM events WHERE seq > ?", (keep,))
    conn.commit()
    conn.execute("""CREATE TRIGGER IF NOT EXISTS prevent_delete
        BEFORE DELETE ON events
        BEGIN
            SELECT RAISE(ABORT, 'DELETE on events table is not allowed');
        END;""")
    conn.commit()
    conn.close()