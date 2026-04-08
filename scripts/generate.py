"""Generate a static HTML vulnerability dashboard from CSV reports."""

import csv
import json
import re
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import git
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
    .p-card.is-pending { background-color: #fff3cd; }
    .purl-cell { font-family: monospace; font-size: 0.8em; word-break: break-all; }
    select.is-dense { width: auto; }
  </style>
</head>
<body>
<div class="p-strip is-shallow">
  <div class="row">
    <div class="col-12">
      <h1>Ubuntu CVE Vulnerability Dashboard</h1>

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
              data-solution-id="{{ distro.dirname | e }}"
              {% if not loop.first %}tabindex="-1"{% endif %}
            >{{ distro.label | e }}
              {%- set cnt = distro.serials[0].rows | length %}
              <span class="p-badge u-no-margin--left" aria-label="{{ cnt }} CVEs">{{ cnt }}</span>
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
            <span class="u-text--muted" id="generated-date-{{ loop.index }}">
              Generated {{ distro.serials[0].generated_date }}
            </span>
          </div>
          <div class="col-6 u-align--right u-vertically-center">
            <a href="{{ distro.solution_url | e }}" target="_blank" rel="noopener noreferrer">
              View VCF solution: {{ distro.label | e }}
            </a>
          </div>
        </div>
        <script type="application/json"
                id="serial-data-{{ loop.index }}">{{ distro.serials_json | safe }}</script>
        <div class="row" id="cards-{{ loop.index }}">
          {% for row in distro.serials[0].rows %}
          {%- set sv = row.severity | lower %}
          {%- if sv == 'critical' or sv == 'high' %}
            {%- set chip = 'p-chip--negative' %}
          {%- elif sv == 'medium' %}
            {%- set chip = 'p-chip--caution' %}
          {%- elif sv == 'low' %}
            {%- set chip = 'p-chip--positive' %}
          {%- else %}
            {%- set chip = 'p-chip' %}
          {%- endif %}
          <div class="col-3 col-medium-3 col-small-4">
            <div class="p-card{% if row.fixed_version == 'pending' %} is-pending{% endif %}">
              <div class="u-clearfix">
                <h4 class="u-no-margin--bottom u-float--left">
                  <a href="{{ row.url | e }}" target="_blank"
                     rel="noopener noreferrer">{{ row.cve_id | e }}</a>
                </h4>
                <span class="u-float--right">
                  <span class="{{ chip }} is-readonly is-inline is-dense">
                    <span class="p-chip__value">{{ row.severity | e }}</span>
                  </span>
                </span>
              </div>
              <hr class="u-sv1" />
              <dl class="u-no-margin--bottom">
                <dt>Package</dt>
                <dd>{{ row.package | e }}</dd>
                <dt>Fix Version</dt>
                <dd>
                  {%- if row.fixed_version == 'pending' %}
                  <span class="p-chip--caution is-readonly is-inline is-dense">
                    <span class="p-chip__value">pending</span>
                  </span>
                  {%- else %}{{ row.fixed_version | e }}{%- endif %}
                </dd>
              </dl>
              <details>
                <summary class="u-text--muted">PURL</summary>
                <p class="purl-cell">{{ row.purl | e }}</p>
              </details>
            </div>
          </div>
          {% endfor %}
        </div>
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

  function buildCard(row) {
    var chipClass = severityChipClass(row.severity);
    var fixHtml = row.fixed_version === 'pending'
      ? '<span class="p-chip--caution is-readonly is-inline is-dense">'
        + '<span class="p-chip__value">pending</span></span>'
      : esc(row.fixed_version);
    var pendingClass = row.fixed_version === 'pending' ? ' is-pending' : '';
    return '<div class="col-3 col-medium-3 col-small-4">'
      + '<div class="p-card' + pendingClass + '">'
      + '<div class="u-clearfix">'
      + '<h4 class="u-no-margin--bottom u-float--left">'
      + '<a href="' + esc(row.url) + '" target="_blank" rel="noopener noreferrer">'
      + esc(row.cve_id) + '</a></h4>'
      + '<span class="u-float--right">'
      + '<span class="' + chipClass + ' is-readonly is-inline is-dense">'
      + '<span class="p-chip__value">' + esc(row.severity) + '</span></span></span>'
      + '</div>'
      + '<hr class="u-sv1" />'
      + '<dl class="u-no-margin--bottom">'
      + '<dt>Package</dt><dd>' + esc(row.package) + '</dd>'
      + '<dt>Fix Version</dt><dd>' + fixHtml + '</dd>'
      + '</dl>'
      + '<details><summary class="u-text--muted">PURL</summary>'
      + '<p class="purl-cell">' + esc(row.purl) + '</p></details>'
      + '</div></div>';
  }

  function switchSerial(paneIdx, serialName) {
    var allSerials = JSON.parse(
      document.getElementById('serial-data-' + paneIdx).textContent
    );
    var entry = allSerials[serialName];
    var container = document.getElementById('cards-' + paneIdx);
    container.innerHTML = entry.rows.map(buildCard).join('');
    var dateEl = document.getElementById('generated-date-' + paneIdx);
    if (dateEl) dateEl.textContent = 'Generated ' + entry.generated_date;
  }

  // --- URL hash navigation ---
  function getActiveState() {
    var activeTab = document.querySelector('[role="tab"][aria-selected="true"]');
    if (!activeTab) return { solutionId: '', serialName: '' };
    var solutionId = activeTab.dataset.solutionId || '';
    var paneId = activeTab.getAttribute('aria-controls');
    var paneIdx = paneId ? paneId.replace('pane-', '') : '';
    var sel = paneIdx ? document.getElementById('serial-select-' + paneIdx) : null;
    var serialName = sel ? sel.value : '';
    return { solutionId: solutionId, serialName: serialName };
  }

  function updateHash() {
    var state = getActiveState();
    if (state.solutionId) {
      window.location.hash = state.serialName
        ? state.solutionId + '/' + state.serialName
        : state.solutionId;
    }
  }

  function applyHash() {
    var hash = window.location.hash.replace(/^#/, '');
    if (!hash) return;
    var parts = hash.split('/');
    var solutionId = parts[0].replace(/[^a-zA-Z0-9._-]/g, '');
    var version = (parts[1] || '').replace(/[^a-zA-Z0-9._-]/g, '');
    var tab = document.querySelector('[role="tab"][data-solution-id="' + solutionId + '"]');
    if (!tab) return;
    document.querySelectorAll('[role="tab"]').forEach(function (t) {
      t.setAttribute('aria-selected', 'false');
      t.setAttribute('tabindex', '-1');
    });
    document.querySelectorAll('[role="tabpanel"]').forEach(function (p) {
      p.hidden = true;
    });
    tab.setAttribute('aria-selected', 'true');
    tab.removeAttribute('tabindex');
    document.getElementById(tab.getAttribute('aria-controls')).hidden = false;
    if (version) {
      var paneId = tab.getAttribute('aria-controls');
      var paneIdx = paneId ? parseInt(paneId.replace('pane-', '')) : null;
      if (paneIdx) {
        var sel = document.getElementById('serial-select-' + paneIdx);
        if (sel) {
          for (var i = 0; i < sel.options.length; i++) {
            if (sel.options[i].value === version) {
              sel.value = version;
              switchSerial(paneIdx, version);
              break;
            }
          }
        }
      }
    }
    updateHash();
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
        updateHash();
      });
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    initTabs();

    // Wire up serial selectors.
    document.querySelectorAll('[id^="serial-select-"]').forEach(function (sel) {
      sel.addEventListener('change', function () {
        switchSerial(parseInt(sel.dataset.paneIdx), sel.value);
        updateHash();
      });
    });

    applyHash();
    window.addEventListener('hashchange', applyHash);
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


def csv_commit_date(repo, path: Path) -> str:
    """Return the UTC ISO-8601 datetime of the most recent commit touching *path*.

    Falls back to the current UTC time if the file has no commits or there is no repo.
    """
    if repo is None:
        return datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    try:
        commits = list(repo.iter_commits(paths=str(path), max_count=1))
        if commits:
            dt = commits[0].committed_datetime.astimezone(UTC)
            return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        pass
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")


def render_html(distros: list[dict]) -> str:
    """Render the dashboard HTML from the distros data structure."""
    env = Environment(autoescape=select_autoescape(["html"]))
    template = env.from_string(_TEMPLATE)
    return template.render(distros=distros)


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

    try:
        repo = git.Repo(root, search_parent_directories=True)
    except git.InvalidGitRepositoryError:
        repo = None

    distros = []
    for label, dirname, csvs in discover_csvs(root):
        serials = [
            {"name": p.stem, "rows": parse_csv(p), "generated_date": csv_commit_date(repo, p)}
            for p in csvs
        ]
        distros.append({
            "label": label,
            "dirname": dirname,
            "solution_url": f"{VCF_BASE_URL}/{dirname}?slug=true",
            "serials": serials,
            # Escape '</' so </script> can't break the JSON data element.
            "serials_json": json.dumps(
                {
                    s["name"]: {"rows": s["rows"], "generated_date": s["generated_date"]}
                    for s in serials
                },
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
