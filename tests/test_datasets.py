from pathlib import Path

import pytest

from app.data.sync_mitre import parse_capec, parse_cwe, safe_extract


def test_parses_cwe_and_capec_relationships(tmp_path: Path) -> None:
    cwe_path = tmp_path / "cwe.xml"
    cwe_path.write_text(
        '<Weakness_Catalog xmlns="urn:cwe"><Weaknesses>'
        '<Weakness ID="494" Name="Download Without Integrity Check" Status="Draft"/>'
        "</Weaknesses></Weakness_Catalog>"
    )
    capec_path = tmp_path / "capec.xml"
    capec_path.write_text(
        '<Attack_Pattern_Catalog xmlns="urn:capec"><Attack_Patterns>'
        '<Attack_Pattern ID="187" Name="Malicious Update" Status="Stable">'
        '<Related_Weaknesses><Related_Weakness CWE_ID="494"/></Related_Weaknesses>'
        "</Attack_Pattern></Attack_Patterns></Attack_Pattern_Catalog>"
    )

    assert parse_cwe(cwe_path)[0]["id"] == "CWE-494"
    patterns, relationships = parse_capec(capec_path)
    assert patterns[0]["id"] == "CAPEC-187"
    assert relationships == [{"cwe": "CWE-494", "capec": "CAPEC-187"}]


def test_rejects_zip_slip(tmp_path: Path) -> None:
    import zipfile

    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../outside.txt", "unsafe")

    with pytest.raises(ValueError, match="unsafe path"):
        safe_extract(archive, tmp_path / "output")
