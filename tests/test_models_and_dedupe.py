from hunternexus.models import Asset, AssetType, Source
from hunternexus.utils.dedupe import dedupe_assets, dedupe_strings


def test_asset_key_case_insensitive():
    a1 = Asset(value="Dev.Example.com", asset_type=AssetType.SUBDOMAIN, source=Source.SEED, target="example.com")
    a2 = Asset(value="dev.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.SEED, target="example.com")
    assert a1.key() == a2.key()


def test_dedupe_assets_merges_sources():
    a1 = Asset(value="dev.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.SUBDOMAIN_PASSIVE, target="example.com")
    a2 = Asset(value="dev.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.GITHUB_RECON, target="example.com")
    merged = dedupe_assets([a1, a2])
    assert len(merged) == 1
    sources = merged[0].metadata["also_found_by"]
    assert "subdomain_passive" in sources
    assert "github_recon" in sources


def test_dedupe_strings():
    out = dedupe_strings(["A.com", "a.com", " b.com ", "", "b.com"])
    assert out == ["a.com", "b.com"]


def test_asset_round_trip_dict():
    a = Asset(value="x.example.com", asset_type=AssetType.SUBDOMAIN, source=Source.SEED, target="example.com", metadata={"k": "v"})
    d = a.to_dict()
    a2 = Asset.from_dict(d)
    assert a2.value == a.value
    assert a2.asset_type == a.asset_type
    assert a2.metadata == {"k": "v"}
