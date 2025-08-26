# Tech Detection XXL

> Collect **the largest open dataset of web technologies** and use multiple detectors (our JSON matcher, WhatWeb, and python‑Wappalyzer) to fingerprint sites reliably. This project’s goal is simple: _cover everything_ — front‑end, back‑end, headless CMS, CDNs, A/B testing, CI/CD, hosting, WAFs, analytics, payments, and more — and make the detections transparent with evidence.
> https://github.com/tomnomnom/wappalyzer/blob/master/src/technologies/a.json (Data Source)
## Vision

I want to **collect data of all web technologies** and, by using these tools together, **build a great project for technology detection**.  
This repo combines:
- **Open dataset** (`web_tech_dataset.json`) — human‑readable fingerprints (headers, cookies, scripts, HTML patterns, DNS) with categories, implies/requires, and evidence scoring.
- **Custom matcher** (`webtech_matcher.py`) — fast, explainable detection using the dataset.
- **WhatWeb integration** — optional CLI engine for additional plugins/signatures.
- **python‑Wappalyzer integration** — optional library to add Wappalyzer’s knowledge (versions & categories).

## Features

- 🔎 **Multi‑engine merge**: dataset + WhatWeb + Wappalyzer into one JSON result.
- 🧾 **Evidence**: show exactly _why_ a technology matched (header lines, cookies, script URLs, HTML snippets).
- 🪪 **Categories**: consistent category names in the dataset; Wappalyzer cats are merged too.
- 🧠 **Rules**: implies / requires / excludes support in the dataset.
- 🪪 **Ultra‑generic heuristics**: example/demo pages, generic titles, etc.
- 🛰 **DNS checks**: optional `--dns` (e.g., CDN CNAME patterns).
- 🧰 **Debug dump**: `--dump` prints headers, cookies, script srcs, HTML title & length.

## Repo layout

```
webtech_matcher.py        # main matcher with WhatWeb + Wappalyzer integration
web_tech_dataset.json     # big fingerprint dataset (JSON)
requirements.txt          # Python deps (requests, bs4, dnspython, python-Wappalyzer, setuptools, ...)
README.md                 # this file
```

## Install

```bash
python -m venv venv
source venv/bin/activate              # Windows: .\venv\Scripts\activate
pip install -r requirements.txt
```

### WhatWeb (optional)

Use your OS package manager or build from source. Example (already working if you have `./whatweb`):
```bash
./whatweb https://www.joomla.org -a 3 --log-json=- | head
```

### python‑Wappalyzer (optional)

Already in `requirements.txt`. If you installed it separately and see `pkg_resources` error, install setuptools:
```bash
pip install --upgrade setuptools python-Wappalyzer
```

## Quick start

Dataset only:
```bash
python webtech_matcher.py https://example.com   --dataset web_tech_dataset.json   --json
```

Dataset + WhatWeb (your local binary):
```bash
python webtech_matcher.py https://www.joomla.org   --dataset web_tech_dataset.json   --whatweb --whatweb-path ./whatweb --whatweb-aggr 3   --json > report.json
```

Dataset + Wappalyzer:
```bash
python webtech_matcher.py https://www.joomla.org   --dataset web_tech_dataset.json   --wappalyzer --wappalyzer-update   --json > report.json
```

All three engines together:
```bash
python webtech_matcher.py https://www.joomla.org   --dataset web_tech_dataset.json   --whatweb --whatweb-path ./whatweb --whatweb-aggr 3   --wappalyzer --wappalyzer-update   --json > merged_report.json
```

Debug your fetch:
```bash
python webtech_matcher.py https://www.joomla.org   --dataset web_tech_dataset.json   --dump --json
```

Analyze a saved HTML file:
```bash
python webtech_matcher.py https://target.tld --html saved.html --json
```

Enable DNS fingerprints:
```bash
python webtech_matcher.py https://target.tld --dns --json
```

## Output (shape)

The matcher prints a single JSON object with:
- `url` — final URL after redirects
- `technologies_detected` — array of detections (merged). Each item includes:
  - `name`, `score` (0–100), `versions`, `categories`, `source` (`dataset` | `whatweb` | `wappalyzer`)
  - `evidence[]` — structured proof of the match (field/detail/match/confidence/version)
- `debug` — when `--dump` is used
- `whatweb_raw` / `wappalyzer_raw` — raw blocks from external engines
- `counts` — matched vs tested

_Minimal example (trimmed):_
```json
{
  "url": "https://www.joomla.org/",
  "technologies_detected": [
    {"name":"Cloudflare", "score":100, "categories":["CDN","Security/WAF/Auth"], "source":"dataset"},
    {"name":"Joomla", "score":50, "categories":["CMS"], "source":"dataset"},
    {"name":"Google-Tag-Manager", "score":65, "categories":["Tag Managers"], "source":"wappalyzer"}
  ],
  "counts": {"matched": 9, "tested": 160}
}
```

## Dataset schema (overview)

```jsonc
{
  "meta": {{ "...": "..." }},
  "categories": {
    "1": "CMS",
    "9": "CDN",
    "11": "Analytics",
    "...": "..."
  },
  "technologies": {
    "Cloudflare": {
      "cats": ["9","Security/WAF/Auth","Edge/Serverless"],
      "headers": { "Server": "(?i)cloudflare", "CF-Ray": ".+" },
      "cookies": { "cfduid": ".*" },
      "scripts": ["cdn-cgi", "rocket\.js"],
      "html": "<!--\s*Cloudflare\s*-->;confidence:40",
      "dns": { "CNAME": ["\.cdn.cloudflare\.net$"] },
      "implies": ["HTTP/3;confidence:10"]
    }
  }
}
```

**Pattern notes**
- Regex are case‑insensitive by default; add `;confidence:N` to weigh signals, `;version:\1` to capture a version group.
- Use `headers`, `cookies`, `scripts`, `html`, `url`, `xhr`, `dns` keys.
- Optional: `implies`, `requires`, `excludes`, `saas`, `oss`, `website`, `description`.

## Troubleshooting

- **WhatWeb not found / no JSON** → point to your binary: `--whatweb-path ./whatweb` or install via your OS package manager.
- **python‑Wappalyzer ‘pkg_resources’** → `pip install --upgrade setuptools`.
- **`Wappalyzer.latest(update=...)` not supported** → our script auto‑falls back; you can also run without `--wappalyzer-update`.
- **Blocked by WAF** → try a different `--user-agent` or add `--no-redirects` and fetch the HTML yourself.

## Roadmap

- Expand dataset (more headless CMS, CDNs, A/B testing, CI/CD, PaaS, WAF, SSG, search, email/chat).
- Category normalization between engines.
- Batch scanning + CSV export + ZIP bundling.
- Per‑tech confidence tuning and version extraction improvements.

## Contributing

1. Fork & branch.
2. Add techs to `web_tech_dataset.json`:
   - Prefer **low‑risk** signals (public headers, unobtrusive script srcs).
   - Keep regex **precise**; avoid over‑matching.
   - Add `website`, `saas/oss`, `cats` (by id or normalized name).
   - Include `implies`/`requires`/`excludes` where helpful.
3. Test locally:
   ```bash
   python webtech_matcher.py https://target --dataset web_tech_dataset.json --json
   ```
4. Open a PR with examples and evidence.

## License

- **Dataset**: CC‑BY‑SA‑4.0 (share alike with attribution).
- **Code**: MIT.

---

**Let’s build the most complete open technology detection dataset on the web.** 🚀
