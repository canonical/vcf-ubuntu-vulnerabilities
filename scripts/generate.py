"""Generate a static HTML vulnerability dashboard from CSV reports."""

import csv
import json
import re
import urllib.request
from datetime import date
from pathlib import Path

from jinja2 import Environment, select_autoescape

_VENDOR_ASSETS = {
    "vanilla-framework.min.css": (
        "https://assets.ubuntu.com/v1/vanilla_framework_version_4_46_0_min.css"
    ),
}

# Maps directory name fragments to human-readable distro labels.
_KNOWN_DISTROS = {
    "jammy": "Ubuntu 22.04 LTS (Jammy)",
    "noble": "Ubuntu 24.04 LTS (Noble)",
    "focal": "Ubuntu 20.04 LTS (Focal)",
    "bionic": "Ubuntu 18.04 LTS (Bionic)",
}

_TEMPLATE = """\
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Ubuntu CVE Vulnerability Dashboard</title>
  <link rel="stylesheet" href="vendor/vanilla-framework.min.css" />
  <style>
    .pending-row { background-color: #fff3cd; }
    .purl-cell   { font-family: monospace; font-size: 0.8em; word-break: break-all; }
    select.is-dense { width: auto; }
  </style>
</head>
<body>
<div class="p-strip is-shallow">
  <div class="row">
    <div class="col-12">
      <h1>Ubuntu CVE Vulnerability Dashboard</h1>
      <p class="u-text--muted">Generated {{ generated_date }}</p>

      <div class="p-tabs">
        <div class="p-tabs__list" role="tablist" aria-label="Ubuntu distributions">
          {% for distro in distros %}
          <div class="p-tabs__item">
            <button
              class="p-tabs__link"
              role="tab"
              id="tab-{{ loop.index }}"
              aria-controls="pane-{{ loop.index }}"
              aria-selected="{% if loop.first %}true{% else %}false{% endif %}"
              {% if not loop.first %}tabindex="-1"{% endif %}
            >{{ distro.label | e }}
              <span class="p-badge u-no-margin--left" aria-label="{{ distro.serials[0].rows | length }} CVEs">{{ distro.serials[0].rows | length }}</span>
            </button>
          </div>
          {% endfor %}
        </div>
      </div>

      {% for distro in distros %}
      <div
        role="tabpanel"
        id="pane-{{ loop.index }}"
        aria-labelledby="tab-{{ loop.index }}"
        {% if not loop.first %}hidden{% endif %}
      >
        <div class="row u-sv1">
          <div class="col-6 u-vertically-center">
            <label for="serial-select-{{ loop.index }}"><strong>Serial:</strong></label>
            <select id="serial-select-{{ loop.index }}"
                    class="is-dense"
                    data-pane-idx="{{ loop.index }}">
              {% for serial in distro.serials %}
              <option value="{{ serial.name | e }}"{% if loop.first %} selected{% endif %}>
                {{ serial.name | e }}
              </option>
              {% endfor %}
            </select>
          </div>
          <div class="col-6 u-align--right u-vertically-center">
            <a href="{{ distro.solution_url | e }}" target="_blank" rel="noopener noreferrer">
              View VCF solution: {{ distro.label | e }}
            </a>
          </div>
        </div>
        <script type="application/json"
                id="serial-data-{{ loop.index }}">{{ distro.serials_json | safe }}</script>
        <table
          class="p-table--mobile-card"
          id="table-{{ loop.index }}"
          aria-label="{{ distro.label | e }} CVE vulnerabilities"
        >
          <thead>
            <tr>
              <th aria-sort="none"><button class="p-table__sort-button">CVE</button></th>
              <th aria-sort="descending"><button class="p-table__sort-button">Severity</button></th>
              <th aria-sort="none"><button class="p-table__sort-button">Package</button></th>
              <th aria-sort="none"><button class="p-table__sort-button">Fix Version</button></th>
              <th>PURL</th>
            </tr>
          </thead>
          <tbody>
            {% for row in distro.serials[0].rows %}
            <tr{% if row.fixed_version == 'pending' %} class="pending-row"{% endif %}>
              <td data-heading="CVE">
                <a href="{{ row.url | e }}" target="_blank" rel="noopener noreferrer">
                  {{ row.cve_id | e }}
                </a>
              </td>
              <td data-heading="Severity">
                <span class="{% if row.severity | lower in ('critical', 'high') %}p-chip--negative{% elif row.severity | lower == 'medium' %}p-chip--caution{% elif row.severity | lower == 'low' %}p-chip--positive{% else %}p-chip{% endif %} is-readonly is-inline is-dense">
                  <span class="p-chip__value">{{ row.severity | e }}</span>
                </span>
              </td>
              <td data-heading="Package">{{ row.package | e }}</td>
              <td data-heading="Fix Version">
                {% if row.fixed_version == 'pending' %}
                <span class="p-chip--caution is-readonly is-inline is-dense">
                  <span class="p-chip__value">pending</span>
                </span>
                {% else %}
                {{ row.fixed_version | e }}
                {% endif %}
              </td>
              <td data-heading="PURL" class="purl-cell">{{ row.purl | e }}</td>
            </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
      {% endfor %}
    </div>
  </div>
</div>

<script>
  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function severityChipClass(sev) {
    var s = sev.toLowerCase();
    if (s === 'critical' || s === 'high') return 'p-chip--negative';
    if (s === 'medium') return 'p-chip--caution';
    if (s === 'low') return 'p-chip--positive';
    return 'p-chip';
  }

  function buildRow(row) {
    var cls = row.fixed_version === 'pending' ? ' class="pending-row"' : '';
    var fixCell = row.fixed_version === 'pending'
      ? '<span class="p-chip--caution is-readonly is-inline is-dense"><span class="p-chip__value">pending</span></span>'
      : esc(row.fixed_version);
    var chipClass = severityChipClass(row.severity);
    return '<tr' + cls + '>'
      + '<td data-heading="CVE"><a href="' + esc(row.url) + '" target="_blank" rel="noopener noreferrer">'
      + esc(row.cve_id) + '</a></td>'
      + '<td data-heading="Severity"><span class="' + chipClass + ' is-readonly is-inline is-dense">'
      + '<span class="p-chip__value">' + esc(row.severity) + '</span></span></td>'
      + '<td data-heading="Package">' + esc(row.package) + '</td>'
      + '<td data-heading="Fix Version">' + fixCell + '</td>'
      + '<td data-heading="PURL" class="purl-cell">' + esc(row.purl) + '</td>'
      + '</tr>';
  }

  function switchSerial(paneIdx, serialName) {
    var allSerials = JSON.parse(
      document.getElementById('serial-data-' + paneIdx).textContent
    );
    document.querySelector('#table-' + paneIdx + ' tbody').innerHTML =
      allSerials[serialName].map(buildRow).join('');
  }

  // --- Tab switching ---
  function initTabs() {
    var tabs = document.querySelectorAll('[role="tab"]');
    tabs.forEach(function (tab) {
      tab.addEventListener('click', function () {
        tabs.forEach(function (t) {
          t.setAttribute('aria-selected', 'false');
          t.setAttribute('tabindex', '-1');
        });
        document.querySelectorAll('[role="tabpanel"]').forEach(function (p) {
          p.hidden = true;
        });
        tab.setAttribute('aria-selected', 'true');
        tab.removeAttribute('tabindex');
        document.getElementById(tab.getAttribute('aria-controls')).hidden = false;
      });
    });
  }

  // --- Column sorting ---
  function getCellText(row, colIdx) {
    return (row.cells[colIdx] ? row.cells[colIdx].textContent.trim() : '');
  }

  function sortTable(table, colIdx, direction) {
    var tbody = table.tBodies[0];
    var rows = Array.prototype.slice.call(tbody.rows);
    rows.sort(function (a, b) {
      var av = getCellText(a, colIdx);
      var bv = getCellText(b, colIdx);
      return direction === 'ascending' ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    rows.forEach(function (r) { tbody.appendChild(r); });
  }

  function initSort(table) {
    var headers = table.querySelectorAll('th[aria-sort]');
    headers.forEach(function (th, colIdx) {
      th.querySelector('.p-table__sort-button').addEventListener('click', function () {
        var current = th.getAttribute('aria-sort');
        var next = current === 'ascending' ? 'descending' : 'ascending';
        headers.forEach(function (h) { h.setAttribute('aria-sort', 'none'); });
        th.setAttribute('aria-sort', next);
        sortTable(table, colIdx, next);
      });
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    initTabs();

    document.querySelectorAll('table[id^="table-"]').forEach(function (table) {
      initSort(table);
      // Apply initial sort by Severity (col 1) descending.
      var sevTh = table.querySelector('thead th:nth-child(2)');
      if (sevTh) {
        sortTable(table, 1, 'descending');
      }
    });

    // Wire up serial selectors.
    document.querySelectorAll('[id^="serial-select-"]').forEach(function (sel) {
      sel.addEventListener('change', function () {
        switchSerial(parseInt(sel.dataset.paneIdx), sel.value);
      });
    });
  });
</script>
</body>
</html>
"""


def distro_label(dirname: str) -> str:
    """Return a human-readable label for a distro directory name."""
    for fragment, label in _KNOWN_DISTROS.items():
        if fragment in dirname:
            return label
    # Fallback: convert hyphens to spaces and title-case.
    return re.sub(r"-+", " ", dirname).title()


def pick_latest_csv(paths: list[Path]) -> Path:
    """Return the lexicographically last CSV path (date-coded filenames sort correctly)."""
    return sorted(paths)[-1]


VCF_BASE_URL = "https://vcf.broadcom.com/vsc/services/details"


def discover_csvs(root: Path) -> list[tuple[str, str, list[Path]]]:
    """Walk *root* and return [(label, dirname, csvs_newest_first)] for each distro directory."""
    result = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        csvs = sorted(child.glob("*.csv"), reverse=True)  # newest first
        if not csvs:
            continue
        result.append((distro_label(child.name), child.name, csvs))
    return result


def parse_csv(path: Path) -> list[dict]:
    """Parse a CSV report and return rows with only the required fields."""
    rows = []
    with path.open(newline="") as f:
        for row in csv.DictReader(f):
            rows.append(
                {
                    "cve_id": row["CVE ID"],
                    "severity": row["Severity"],
                    "package": row["Package Name"],
                    "fixed_version": row["Fixed Version"],
                    "purl": row["PURL"],
                    "url": row["URL"],
                }
            )
    return rows


def render_html(distros: list[dict]) -> str:
    """Render the dashboard HTML from the distros data structure."""
    env = Environment(autoescape=select_autoescape(["html"]))
    template = env.from_string(_TEMPLATE)
    return template.render(
        distros=distros,
        generated_date=date.today().isoformat(),
    )


def fetch_vendor_assets(dist: Path) -> None:
    """Download vendored CSS/JS assets into dist/vendor/ (skips existing files)."""
    vendor = dist / "vendor"
    vendor.mkdir(exist_ok=True)
    for filename, url in _VENDOR_ASSETS.items():
        dest = vendor / filename
        if not dest.exists():
            print(f"Downloading {filename}...")
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req) as resp, dest.open("wb") as f:  # noqa: S310
                f.write(resp.read())


def main() -> None:
    root = Path(__file__).parent.parent
    dist = root / "dist"
    dist.mkdir(exist_ok=True)

    fetch_vendor_assets(dist)

    distros = []
    for label, dirname, csvs in discover_csvs(root):
        serials = [{"name": p.stem, "rows": parse_csv(p)} for p in csvs]
        distros.append({
            "label": label,
            "solution_url": f"{VCF_BASE_URL}/{dirname}?slug=true",
            "serials": serials,
            # Escape '</' so </script> can't break the JSON data element.
            "serials_json": json.dumps(
                {s["name"]: s["rows"] for s in serials},
                ensure_ascii=False,
            ).replace("</", "<\\/"),
        })

    html = render_html(distros)
    out = dist / "index.html"
    out.write_text(html, encoding="utf-8")
    latest_rows = sum(len(d["serials"][0]["rows"]) for d in distros)
    print(f"Written: {out}  ({len(distros)} distro(s), {latest_rows} rows in latest serials)")


if __name__ == "__main__":
    main()
