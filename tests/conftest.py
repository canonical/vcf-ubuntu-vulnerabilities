"""Shared fixtures for the report generator tests."""

import csv

import pytest

SAMPLE_HEADERS = [
    "CVE ID",
    "Severity",
    "Score",
    "Image+Version",
    "Distro",
    "Package Name",
    "Title",
    "URL",
    "Installed Version",
    "Fixed Version",
    "Description",
    "Published Date",
    "PURL",
]


def _write_csv(path, rows):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=SAMPLE_HEADERS)
        writer.writeheader()
        writer.writerows(rows)


@pytest.fixture()
def sample_rows():
    return [
        {
            "CVE ID": "CVE-2026-0001",
            "Severity": "high",
            "Score": "",
            "Image+Version": "20260312",
            "Distro": "jammy",
            "Package Name": "libfoo",
            "Title": "",
            "URL": "https://ubuntu.com/security/CVE-2026-0001",
            "Installed Version": "1.0.0-1",
            "Fixed Version": "1.0.0-2",
            "Description": "",
            "Published Date": "",
            "PURL": "pkg:deb/ubuntu/libfoo@1.0.0-1?distro=jammy",
        },
        {
            "CVE ID": "CVE-2026-0002",
            "Severity": "unknown",
            "Score": "",
            "Image+Version": "20260312",
            "Distro": "jammy",
            "Package Name": "libbar",
            "Title": "",
            "URL": "https://ubuntu.com/security/CVE-2026-0002",
            "Installed Version": "2.1.0-3",
            "Fixed Version": "pending",
            "Description": "",
            "Published Date": "",
            "PURL": "pkg:deb/ubuntu/libbar@2.1.0-3?distro=jammy",
        },
    ]


@pytest.fixture()
def repo_tree(tmp_path, sample_rows):
    """A minimal repo directory tree with two distro CSV directories."""
    jammy_dir = tmp_path / "ubuntu-22-04-lts-jammy-2"
    jammy_dir.mkdir()
    _write_csv(jammy_dir / "22.04.20260101.csv", sample_rows)
    _write_csv(jammy_dir / "22.04.20260312.csv", sample_rows)

    noble_dir = tmp_path / "ubuntu-24-04-lts-noble-2"
    noble_dir.mkdir()
    _write_csv(noble_dir / "24.04.20260313.csv", sample_rows)

    # Non-CSV directory — should be ignored by discovery
    (tmp_path / "some-other-dir").mkdir()

    return tmp_path
