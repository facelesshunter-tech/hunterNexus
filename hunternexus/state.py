"""Persistent attack-surface inventory (SQLite).

This provides an attack-surface inventory / asset database with
continuous recon / change-detection: every asset ever seen for a target
is stored with a first_seen timestamp, so a later re-run can report *new*
assets since the last scan -- the same underlying "recon is a cycle" idea
as a Gungnir-style continuous-monitoring setup, without requiring an
actual always-on CT-log watcher.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Iterable, Optional

from hunternexus.models import Asset, AssetType, Source

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    key TEXT NOT NULL,
    target TEXT NOT NULL,
    value TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    sources TEXT NOT NULL,      -- JSON list
    metadata TEXT NOT NULL,     -- JSON object
    PRIMARY KEY (target, key)
);
CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target);
CREATE INDEX IF NOT EXISTS idx_assets_first_seen ON assets(first_seen);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at REAL NOT NULL,
    finished_at REAL,
    stages_run TEXT NOT NULL    -- JSON list
);
"""


class AssetStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ---- writes -----------------------------------------------------

    def upsert(self, asset: Asset) -> bool:
        """Returns True if this is a brand-new asset (never seen before
        for this target) -- the signal the change-detection report uses."""
        now = time.time()
        cur = self.conn.execute(
            "SELECT sources, metadata FROM assets WHERE target=? AND key=?",
            (asset.target, asset.key()),
        )
        row = cur.fetchone()
        # dedupe_assets() (called before upsert_many() in every real
        # pipeline run) already merges every tool that found this exact
        # asset into metadata["also_found_by"] -- but the `sources` column
        # was only ever being seeded from the single asset.source value of
        # whichever Asset object happened to "win" the in-memory dedup,
        # silently losing every other contributor. Confirmed live: an
        # asset crt.sh AND subfinder both found showed only "subfinder" in
        # the source-reliability scorecard. also_found_by is the
        # authoritative list; fall back to the single source for callers
        # that bypass dedupe_assets() and call upsert() directly.
        contributing_sources = asset.metadata.get("also_found_by") or [asset.source.value]
        if row is None:
            self.conn.execute(
                "INSERT INTO assets (key, target, value, asset_type, first_seen, last_seen, sources, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    asset.key(),
                    asset.target,
                    asset.value,
                    asset.asset_type.value,
                    now,
                    now,
                    json.dumps(sorted(contributing_sources)),
                    json.dumps(asset.metadata),
                ),
            )
            self.conn.commit()
            return True
        else:
            sources = set(json.loads(row[0]))
            sources.update(contributing_sources)
            metadata = json.loads(row[1])
            metadata.update(asset.metadata)
            self.conn.execute(
                "UPDATE assets SET last_seen=?, sources=?, metadata=? WHERE target=? AND key=?",
                (now, json.dumps(sorted(sources)), json.dumps(metadata), asset.target, asset.key()),
            )
            self.conn.commit()
            return False

    def upsert_many(self, assets: Iterable[Asset]) -> list[Asset]:
        """Returns the subset that were brand-new this run."""
        new_ones = []
        for a in assets:
            if self.upsert(a):
                new_ones.append(a)
        return new_ones

    def start_scan(self, target: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO scans (target, started_at, stages_run) VALUES (?, ?, ?)",
            (target, time.time(), json.dumps([])),
        )
        self.conn.commit()
        return cur.lastrowid

    def finish_scan(self, scan_id: int, stages_run: list[str]) -> None:
        self.conn.execute(
            "UPDATE scans SET finished_at=?, stages_run=? WHERE id=?",
            (time.time(), json.dumps(stages_run), scan_id),
        )
        self.conn.commit()

    # ---- reads -----------------------------------------------------

    def all_for_target(self, target: str, asset_type: Optional[AssetType] = None) -> list[dict]:
        if asset_type:
            cur = self.conn.execute(
                "SELECT value, asset_type, first_seen, last_seen, sources, metadata "
                "FROM assets WHERE target=? AND asset_type=? ORDER BY value",
                (target, asset_type.value),
            )
        else:
            cur = self.conn.execute(
                "SELECT value, asset_type, first_seen, last_seen, sources, metadata "
                "FROM assets WHERE target=? ORDER BY asset_type, value",
                (target,),
            )
        rows = []
        for value, atype, first_seen, last_seen, sources, metadata in cur.fetchall():
            rows.append(
                {
                    "value": value,
                    "asset_type": atype,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "sources": json.loads(sources),
                    "metadata": json.loads(metadata),
                }
            )
        return rows

    def new_since(self, target: str, since_epoch: float) -> list[dict]:
        """The core of the change-detection / 'attack-surface growth
        tracker' capability: assets whose first_seen is after a given
        timestamp, i.e. everything that's appeared since the last check."""
        cur = self.conn.execute(
            "SELECT value, asset_type, first_seen, sources, metadata "
            "FROM assets WHERE target=? AND first_seen > ? ORDER BY first_seen",
            (target, since_epoch),
        )
        rows = []
        for value, atype, first_seen, sources, metadata in cur.fetchall():
            rows.append(
                {
                    "value": value,
                    "asset_type": atype,
                    "first_seen": first_seen,
                    "sources": json.loads(sources),
                    "metadata": json.loads(metadata),
                }
            )
        return rows

    def source_reliability(self, target: Optional[str] = None) -> dict[str, int]:
        """The 'recon-source reliability scorecard' idea: counts how many
        assets each technique has contributed, across one or all targets."""
        if target:
            cur = self.conn.execute("SELECT sources FROM assets WHERE target=?", (target,))
        else:
            cur = self.conn.execute("SELECT sources FROM assets")
        counts: dict[str, int] = {}
        for (sources_json,) in cur.fetchall():
            for s in json.loads(sources_json):
                counts[s] = counts.get(s, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))
