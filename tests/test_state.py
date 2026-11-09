import tempfile
import time
from pathlib import Path

from hunternexus.models import Asset, AssetType, Source
from hunternexus.state import AssetStore


def test_upsert_tracks_new_vs_seen():
    with tempfile.TemporaryDirectory() as tmp:
        store = AssetStore(Path(tmp) / "assets.db")
        a = Asset(value="dev.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.SEED, target="example.com")
        assert store.upsert(a) is True   # brand new
        assert store.upsert(a) is False  # already seen
        store.close()


def test_new_since_filters_by_timestamp():
    with tempfile.TemporaryDirectory() as tmp:
        store = AssetStore(Path(tmp) / "assets.db")
        cutoff = time.time()
        time.sleep(0.01)
        a = Asset(value="new.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.SEED, target="example.com")
        store.upsert(a)
        new = store.new_since("example.com", cutoff)
        assert len(new) == 1
        assert new[0]["value"] == "new.example.com"
        store.close()


def test_source_reliability_counts():
    with tempfile.TemporaryDirectory() as tmp:
        store = AssetStore(Path(tmp) / "assets.db")
        store.upsert(Asset(value="a.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.SUBDOMAIN_PASSIVE, target="example.com"))
        store.upsert(Asset(value="b.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.SUBDOMAIN_PASSIVE, target="example.com"))
        store.upsert(Asset(value="c.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.GITHUB_RECON, target="example.com"))
        counts = store.source_reliability("example.com")
        assert counts["subdomain_passive"] == 2
        assert counts["github_recon"] == 1
        store.close()


def test_source_reliability_counts_every_also_found_by_contributor():
    """Regression test for the scorecard gap found live against example.com:
    an asset multiple tools found (tracked in metadata["also_found_by"] by
    dedupe_assets() before upsert() is ever called) must count toward
    EVERY contributing tool's total, not just whichever Asset object
    happened to "win" the in-memory dedup and get its .source persisted."""
    with tempfile.TemporaryDirectory() as tmp:
        store = AssetStore(Path(tmp) / "assets.db")
        # Simulates what dedupe_assets() hands to upsert_many(): one Asset
        # object, single .source, but metadata already lists every tool
        # that actually found it this run.
        merged = Asset(
            value="shared.example.com",
            asset_type=AssetType.SUBDOMAIN,
            source=Source.SUBFINDER,
            target="example.com",
            metadata={"also_found_by": ["subfinder", "crtsh"]},
        )
        store.upsert(merged)
        counts = store.source_reliability("example.com")
        assert counts["subfinder"] == 1
        assert counts["crtsh"] == 1
        store.close()


def test_source_reliability_merges_also_found_by_on_repeat_upsert():
    """A second scan run that finds the same asset via a different tool
    (also captured in also_found_by) must add to the running sources set,
    not just re-add the single primary source again."""
    with tempfile.TemporaryDirectory() as tmp:
        store = AssetStore(Path(tmp) / "assets.db")
        store.upsert(
            Asset(value="x.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.SUBFINDER,
                  target="example.com", metadata={"also_found_by": ["subfinder"]})
        )
        store.upsert(
            Asset(value="x.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.ASSETFINDER,
                  target="example.com", metadata={"also_found_by": ["assetfinder"]})
        )
        counts = store.source_reliability("example.com")
        assert counts["subfinder"] == 1
        assert counts["assetfinder"] == 1
        store.close()
