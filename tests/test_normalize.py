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
    assert {source.name for source in record.sources} == {"CVE.org", "NVD"}
