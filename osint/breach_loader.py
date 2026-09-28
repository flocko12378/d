#!/usr/bin/env python3
"""
breach_loader.py — import breach dump files into local SQLite FTS5 database
Supports: email:pass, user:pass, email:hash, any colon-separated format

Usage:
  python breach_loader.py import  <file_or_folder>  [--source "COMB"]
  python breach_loader.py search  <query>
  python breach_loader.py stats
"""

import sqlite3, os, sys, re, time, argparse
from pathlib import Path

DB_PATH = os.path.join(os.path.dirname(__file__), "breach.db")

# ─── DB SETUP ──────────────────────────────────────────────────────────────────

def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=-256000")  # 256MB cache
    conn.execute("""
        CREATE TABLE IF NOT EXISTS records (
            id       INTEGER PRIMARY KEY,
            source   TEXT,
            left_    TEXT,    -- email or username (left of colon)
            right_   TEXT,    -- password or hash  (right of colon)
            raw      TEXT     -- original line
        )
    """)
    # FTS5 virtual table for fast full-text search
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS records_fts
        USING fts5(left_, right_, source, content=records, content_rowid=id)
    """)
    # triggers to keep FTS in sync
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS records_ai AFTER INSERT ON records BEGIN
            INSERT INTO records_fts(rowid, left_, right_, source)
            VALUES (new.id, new.left_, new.right_, new.source);
        END
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS records_ad AFTER DELETE ON records BEGIN
            INSERT INTO records_fts(records_fts, rowid, left_, right_, source)
            VALUES ('delete', old.id, old.left_, old.right_, old.source);
        END
    """)
    conn.commit()
    return conn

# ─── IMPORT ────────────────────────────────────────────────────────────────────

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def parse_line(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None, None
    # handle tab-separated too
    if "\t" in line and ":" not in line:
        parts = line.split("\t", 1)
    else:
        # split on first colon only
        parts = line.split(":", 1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    return line, ""

def import_file(conn, path: str, source: str, batch_size=50000):
    path = Path(path)
    if not path.exists():
        print(f"  [!] File not found: {path}")
        return 0

    print(f"  [*] Importing {path.name} (source={source!r})")
    start   = time.time()
    total   = 0
    skipped = 0
    batch   = []

    encodings = ["utf-8", "latin-1", "cp1252", "utf-16"]

    for enc in encodings:
        try:
            with open(path, "r", encoding=enc, errors="replace") as f:
                for line in f:
                    left, right = parse_line(line)
                    if left is None:
                        skipped += 1
                        continue
                    batch.append((source, left.lower(), right, f"{left}:{right}"))
                    total += 1

                    if len(batch) >= batch_size:
                        conn.executemany(
                            "INSERT INTO records (source,left_,right_,raw) VALUES (?,?,?,?)",
                            batch
                        )
                        conn.commit()
                        batch.clear()
                        elapsed = time.time() - start
                        rate    = total / elapsed if elapsed > 0 else 0
                        print(f"    → {total:,} lines  ({rate:,.0f}/s)", end="\r", flush=True)
            break
        except UnicodeDecodeError:
            continue

    if batch:
        conn.executemany(
            "INSERT INTO records (source,left_,right_,raw) VALUES (?,?,?,?)",
            batch
        )
        conn.commit()

    elapsed = time.time() - start
    print(f"    → {total:,} records imported in {elapsed:.1f}s ({skipped} skipped)   ")
    return total

def import_folder(conn, folder: str, source: str):
    folder = Path(folder)
    files  = sorted(folder.rglob("*.txt")) + sorted(folder.rglob("*.csv"))
    print(f"  [*] Found {len(files)} file(s) in {folder}")
    grand_total = 0
    for f in files:
        src = source or f.stem
        grand_total += import_file(conn, f, src)
    print(f"\n  [✓] Total imported: {grand_total:,} records")

# ─── SEARCH ────────────────────────────────────────────────────────────────────

def search(conn, query: str, limit=50):
    query = query.strip().lower()
    results = []

    # FTS5 search (searches left_ and right_ columns)
    # Use prefix match for partial queries
    fts_query = f'"{query}"'   # exact phrase first
    try:
        rows = conn.execute(
            """
            SELECT r.source, r.left_, r.right_
            FROM records_fts fts
            JOIN records r ON r.id = fts.rowid
            WHERE records_fts MATCH ?
            LIMIT ?
            """,
            (fts_query, limit)
        ).fetchall()
        results.extend(rows)
    except Exception:
        pass

    # fallback: LIKE search on left_ (email match)
    if len(results) < 5:
        rows2 = conn.execute(
            "SELECT source, left_, right_ FROM records WHERE left_ LIKE ? LIMIT ?",
            (f"%{query}%", limit)
        ).fetchall()
        # deduplicate
        seen = {(r[1], r[2]) for r in results}
        for r in rows2:
            if (r[1], r[2]) not in seen:
                results.append(r)
                seen.add((r[1], r[2]))

    return results[:limit]

def search_email(conn, email: str, limit=50):
    email = email.strip().lower()
    rows = conn.execute(
        "SELECT source, left_, right_ FROM records WHERE left_ = ? LIMIT ?",
        (email, limit)
    ).fetchall()
    return rows

def search_password(conn, password: str, limit=50):
    rows = conn.execute(
        "SELECT source, left_, right_ FROM records WHERE right_ = ? LIMIT ?",
        (password, limit)
    ).fetchall()
    return rows

def search_domain(conn, domain: str, limit=200):
    domain = domain.strip().lower().lstrip("@")
    rows = conn.execute(
        "SELECT source, left_, right_ FROM records WHERE left_ LIKE ? LIMIT ?",
        (f"%@{domain}", limit)
    ).fetchall()
    return rows

# ─── STATS ─────────────────────────────────────────────────────────────────────

def stats(conn):
    total = conn.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    print(f"\n  Total records : {total:,}")
    print(f"  DB path       : {DB_PATH}")
    size = os.path.getsize(DB_PATH) / (1024**3) if os.path.exists(DB_PATH) else 0
    print(f"  DB size       : {size:.2f} GB\n")
    print(f"  {'Source':<30} {'Count':>12}")
    print("  " + "─"*44)
    sources = conn.execute(
        "SELECT source, COUNT(*) as c FROM records GROUP BY source ORDER BY c DESC LIMIT 20"
    ).fetchall()
    for src, cnt in sources:
        print(f"  {src:<30} {cnt:>12,}")

# ─── CLI ───────────────────────────────────────────────────────────────────────

def cmd_search(conn, query, mode="auto"):
    G = "\033[92m"; R = "\033[91m"; C = "\033[96m"; W = "\033[0m"

    if mode == "email" or (mode == "auto" and "@" in query and "." in query.split("@")[-1]):
        results = search_email(conn, query)
        label   = "exact email"
    elif mode == "domain" or (mode == "auto" and query.startswith("@")):
        results = search_domain(conn, query.lstrip("@"))
        label   = "domain"
    elif mode == "password":
        results = search_password(conn, query)
        label   = "password"
    else:
        results = search(conn, query)
        label   = "full-text"

    print(f"\n  {C}[SEARCH]{W} query={query!r} mode={label} → {len(results)} result(s)\n")

    if not results:
        print(f"  {G}[✓] Not found in local breach database{W}")
        return

    print(f"  {'Source':<25} {'Left (email/user)':<35} {'Right (pass/hash)'}")
    print("  " + "─"*85)
    for source, left_, right_ in results:
        color = R if right_ and len(right_) < 64 else C   # likely plaintext if short
        print(f"  {source:<25} {left_:<35} {color}{right_}{W}")

def main():
    parser = argparse.ArgumentParser(description="Breach database loader + searcher")
    sub = parser.add_subparsers(dest="cmd")

    p_import = sub.add_parser("import", help="Import breach dump file(s)")
    p_import.add_argument("path", help="File or folder to import")
    p_import.add_argument("--source", default="unknown", help="Label for this dump (e.g. 'COMB')")

    p_search = sub.add_parser("search", help="Search the database")
    p_search.add_argument("query", help="Email, username, domain (@domain.com), or password")
    p_search.add_argument("--mode", choices=["auto","email","domain","password","fts"], default="auto")

    sub.add_parser("stats", help="Show database statistics")

    args = parser.parse_args()
    conn = get_conn()

    if args.cmd == "import":
        p = Path(args.path)
        if p.is_dir():
            import_folder(conn, p, args.source)
        else:
            import_file(conn, p, args.source)

    elif args.cmd == "search":
        cmd_search(conn, args.query, args.mode)

    elif args.cmd == "stats":
        stats(conn)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
