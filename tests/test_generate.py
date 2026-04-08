"""Tests for the static HTML report generator."""

import re

from scripts.generate import (
    VCF_BASE_URL,
    csv_commit_date,
    discover_csvs,
    distro_label,
    parse_csv,
    pick_latest_csv,
    render_html,
)


class TestDistroLabel:
    def test_jammy_dirname(self):
        assert distro_label("ubuntu-22-04-lts-jammy-2") == "Ubuntu 22.04 LTS (Jammy)"

    def test_noble_dirname(self):
        assert distro_label("ubuntu-24-04-lts-noble-2") == "Ubuntu 24.04 LTS (Noble)"

    def test_unknown_dirname_falls_back_to_titlecase(self):
        # Unknown names should be returned in a reasonable human-readable form
        # rather than raising an error.
        label = distro_label("ubuntu-99-04-lts-future-1")
        assert isinstance(label, str)
        assert len(label) > 0


class TestPickLatestCsv:
    def test_returns_lexicographically_last(self, tmp_path):
        paths = [
            tmp_path / "22.04.20260101.csv",
            tmp_path / "22.04.20260312.csv",
            tmp_path / "22.04.20251201.csv",
        ]
        assert pick_latest_csv(paths) == tmp_path / "22.04.20260312.csv"

    def test_single_file(self, tmp_path):
        paths = [tmp_path / "22.04.20260101.csv"]
        assert pick_latest_csv(paths) == tmp_path / "22.04.20260101.csv"


class TestDiscoverCsvs:
    def test_finds_both_distro_directories(self, repo_tree):
        result = discover_csvs(repo_tree)
        assert len(result) == 2

    def test_returns_correct_labels(self, repo_tree):
        result = discover_csvs(repo_tree)
        labels = [label for label, _dirname, _path in result]
        assert "Ubuntu 22.04 LTS (Jammy)" in labels
        assert "Ubuntu 24.04 LTS (Noble)" in labels

    def test_returns_dirname(self, repo_tree):
        result = discover_csvs(repo_tree)
        dirnames = [dirname for _label, dirname, _path in result]
        assert "ubuntu-22-04-lts-jammy-2" in dirnames
        assert "ubuntu-24-04-lts-noble-2" in dirnames

    def test_picks_latest_csv_per_distro(self, repo_tree):
        result = discover_csvs(repo_tree)
        jammy_csvs = next(csvs for label, _dirname, csvs in result if "Jammy" in label)
        # newest first: 20260312 should be index 0
        assert "20260312" in jammy_csvs[0].name

    def test_returns_all_csvs_per_distro(self, repo_tree):
        result = discover_csvs(repo_tree)
        jammy_csvs = next(csvs for label, _dirname, csvs in result if "Jammy" in label)
        # conftest creates 20260101 and 20260312
        assert len(jammy_csvs) == 2

    def test_csvs_sorted_newest_first(self, repo_tree):
        result = discover_csvs(repo_tree)
        jammy_csvs = next(csvs for label, _dirname, csvs in result if "Jammy" in label)
        names = [p.stem for p in jammy_csvs]
        assert names == sorted(names, reverse=True)

    def test_ignores_non_csv_directories(self, repo_tree):
        result = discover_csvs(repo_tree)
        labels = [label for label, _dirname, _csvs in result]
        assert not any("some-other" in label.lower() for label in labels)


class TestParseCsv:
    def test_returns_list_of_dicts(self, repo_tree):
        csv_path = repo_tree / "ubuntu-22-04-lts-jammy-2" / "22.04.20260312.csv"
        rows = parse_csv(csv_path)
        assert isinstance(rows, list)
        assert len(rows) == 2

    def test_contains_only_required_columns(self, repo_tree):
        csv_path = repo_tree / "ubuntu-22-04-lts-jammy-2" / "22.04.20260312.csv"
        rows = parse_csv(csv_path)
        expected_keys = {"cve_id", "severity", "package", "fixed_version", "purl", "url"}
        assert set(rows[0].keys()) == expected_keys

    def test_high_severity_row(self, repo_tree):
        csv_path = repo_tree / "ubuntu-22-04-lts-jammy-2" / "22.04.20260312.csv"
        rows = parse_csv(csv_path)
        high = next(r for r in rows if r["severity"] == "high")
        assert high["cve_id"] == "CVE-2026-0001"
        assert high["package"] == "libfoo"
        assert high["fixed_version"] == "1.0.0-2"
        assert "libfoo" in high["purl"]

    def test_pending_fix_version_preserved(self, repo_tree):
        csv_path = repo_tree / "ubuntu-22-04-lts-jammy-2" / "22.04.20260312.csv"
        rows = parse_csv(csv_path)
        pending = next(r for r in rows if r["fixed_version"] == "pending")
        assert pending["cve_id"] == "CVE-2026-0002"


class TestCsvCommitDate:
    _UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$")

    def test_returns_utc_timestamp_when_repo_is_none(self, tmp_path):
        result = csv_commit_date(None, tmp_path / "any.csv")
        assert self._UTC_PATTERN.match(result), f"Unexpected format: {result!r}"

    def test_returns_utc_timestamp_when_file_not_in_git(self, tmp_path):
        """Files in a real git repo but not yet committed fall back to current UTC time."""
        import git
        repo = git.Repo.init(tmp_path)
        csv_path = tmp_path / "untracked.csv"
        csv_path.write_text("data")
        result = csv_commit_date(repo, csv_path)
        assert self._UTC_PATTERN.match(result), f"Unexpected format: {result!r}"

    def test_returns_commit_utc_timestamp_for_committed_file(self, tmp_path):
        import git
        repo = git.Repo.init(tmp_path)
        repo.config_writer().set_value("user", "name", "Test").release()
        repo.config_writer().set_value("user", "email", "t@t.com").release()
        csv_path = tmp_path / "report.csv"
        csv_path.write_text("data")
        repo.index.add(["report.csv"])
        repo.index.commit("add report")
        result = csv_commit_date(repo, csv_path)
        assert self._UTC_PATTERN.match(result), f"Unexpected format: {result!r}"


# Shared minimal distro fixture for render_html tests.
_SAMPLE_ROW = {
    "cve_id": "CVE-2026-0001",
    "severity": "high",
    "package": "libfoo",
    "fixed_version": "1.0.0-2",
    "purl": "pkg:deb/ubuntu/libfoo@1.0.0-1?distro=jammy",
    "url": "https://ubuntu.com/security/CVE-2026-0001",
}
_PENDING_ROW = {
    "cve_id": "CVE-2026-0002",
    "severity": "unknown",
    "package": "libbar",
    "fixed_version": "pending",
    "purl": "pkg:deb/ubuntu/libbar@2.1.0-3?distro=jammy",
    "url": "https://ubuntu.com/security/CVE-2026-0002",
}


def _make_distro(rows=None, extra_serial=False):
    import json
    serials = [{"name": "22.04.20260312", "rows": rows or [_SAMPLE_ROW],
                 "generated_date": "2026-03-12 09:00 UTC"}]
    if extra_serial:
        serials.append({"name": "22.04.20260101", "rows": rows or [_SAMPLE_ROW],
                        "generated_date": "2026-01-01 12:00 UTC"})
    return {
        "label": "Ubuntu 22.04 LTS (Jammy)",
        "dirname": "ubuntu-22-04-lts-jammy-2",
        "solution_url": f"{VCF_BASE_URL}/ubuntu-22-04-lts-jammy-2?slug=true",
        "serials": serials,
        "serials_json": json.dumps(
            {s["name"]: {"rows": s["rows"], "generated_date": s["generated_date"]} for s in serials}
        ),
    }


class TestRenderHtml:
    def test_returns_string(self):
        html = render_html([_make_distro()])
        assert isinstance(html, str)

    def test_html_contains_distro_label(self):
        html = render_html([_make_distro()])
        assert "Ubuntu 22.04 LTS (Jammy)" in html

    def test_html_contains_solution_url(self):
        html = render_html([_make_distro()])
        assert "ubuntu-22-04-lts-jammy-2?slug=true" in html

    def test_html_contains_cve_id(self):
        html = render_html([_make_distro()])
        assert "CVE-2026-0001" in html

    def test_html_pending_fix_in_output(self):
        html = render_html([_make_distro(rows=[_PENDING_ROW])])
        assert "pending" in html

    def test_html_contains_serial_select(self):
        html = render_html([_make_distro(extra_serial=True)])
        assert 'serial-select-1' in html
        assert '22.04.20260312' in html
        assert '22.04.20260101' in html

    def test_html_first_serial_is_selected(self):
        html = render_html([_make_distro(extra_serial=True)])
        # 'selected' should appear on the newest serial option
        idx_newest = html.index('22.04.20260312')
        idx_oldest = html.index('22.04.20260101')
        idx_selected = html.index(' selected')
        assert idx_newest < idx_selected < idx_oldest

    def test_html_contains_serial_json_data(self):
        html = render_html([_make_distro()])
        assert 'serial-data-1' in html
        assert '22.04.20260312' in html

    def test_html_contains_data_solution_id(self):
        html = render_html([_make_distro()])
        assert 'data-solution-id="ubuntu-22-04-lts-jammy-2"' in html

    def test_html_contains_update_hash_function(self):
        html = render_html([_make_distro()])
        assert 'updateHash' in html

    def test_html_contains_apply_hash_function(self):
        html = render_html([_make_distro()])
        assert 'applyHash' in html

    def test_html_contains_hashchange_listener(self):
        html = render_html([_make_distro()])
        assert 'hashchange' in html
