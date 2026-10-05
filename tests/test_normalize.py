from app.ingestion.normalize import normalize


def test_normalizes_and_merges_authoritative_records() -> None:
    cve_org = {
        "cveMetadata": {"datePublished": "2024-03-29T00:00:00Z"},
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "CVE description"}],
                "affected": [
                    {
                        "vendor": "XZ Utils",
                        "product": "xz",
                        "platforms": ["Linux"],
                        "versions": [{"version": "5.6.0", "status": "affected"}],
                    }
                ],
                "problemTypes": [{"descriptions": [{"cweId": "CWE-506"}]}],
                "references": [{"url": "https://example.com/vendor", "tags": ["vendor advisory"]}],
            }
        },
    }
    nvd = {
        "vulnerabilities": [
            {
                "cve": {
                    "published": "2024-03-29T17:15:07.120",
                    "descriptions": [{"lang": "en", "value": "NVD description"}],
                    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-506"}]}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL",
                                    "attackVector": "NETWORK",
                                }
                            }
                        ]
                    },
                    "references": [{"url": "https://example.com/research", "tags": ["Exploit"]}],
                }
            }
        ]
    }

    record = normalize("CVE-2024-3094", cve_org, nvd)

    assert record.description == "NVD description"
    assert record.cwe_ids == ["CWE-506"]
    assert record.cvss and record.cvss.base_score == 10.0
    assert record.affected_products[0].platforms == ["Linux"]
    assert len(record.references) == 2
    assert {source.name for source in record.sources} == {"CVE List V5", "NVD"}


def test_preserves_cvelist_capec_cvss_workaround_and_version_range() -> None:
    record = normalize(
        "CVE-2026-22306",
        {
            "cveMetadata": {},
            "containers": {
                "cna": {
                    "affected": [{
                        "vendor": "Ozols Grupa",
                        "product": "OZOLS",
                        "platforms": ["Windows"],
                        "versions": [{
                            "status": "affected",
                            "version": "0",
                            "lessThan": "1.1.1233",
                        }],
                    }],
                    "impacts": [{"capecId": "CAPEC-187"}],
                    "metrics": [{"cvssV4_0": {
                        "version": "4.0", "baseScore": 10, "baseSeverity": "CRITICAL"
                    }}],
                    "workarounds": [{"lang": "en", "value": "Disable the update job"}],
                }
            },
        },
        None,
    )

    assert record.capec_ids == ["CAPEC-187"]
    assert record.cvss and record.cvss.version == "4.0"
    assert record.affected_products[0].versions == [">=0, <1.1.1233"]
    assert record.workarounds == ["Disable the update job"]


def test_collapses_description_whitespace() -> None:
    record = normalize(
        "CVE-2026-33557",
        None,
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [
                            {"lang": "en", "value": "Attacker  sends\n\ncrafted\u00a0token"}
                        ]
                    }
                }
            ]
        },
    )
    assert record.description == "Attacker sends crafted token"
