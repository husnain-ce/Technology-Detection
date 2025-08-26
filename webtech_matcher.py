#!/usr/bin/env python3
# Patched robust script (dataset + WhatWeb + python-Wappalyzer, version-compatible)
import argparse, json, re, sys, os, subprocess, tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
import requests
from requests.exceptions import RequestException
from bs4 import BeautifulSoup

try:
    import dns.resolver  # type: ignore
    DNS_AVAILABLE = True
except Exception:
    DNS_AVAILABLE = False

DEFAULT_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"

try:
    from Wappalyzer import Wappalyzer as PyWappalyzer, WebPage as PyWebPage  # type: ignore
    WAPPALYZER_AVAILABLE = True
except Exception:
    WAPPALYZER_AVAILABLE = False

@dataclass
class CompiledPattern:
    raw: str
    regex: re.Pattern
    confidence: int = 50
    version_group: Optional[int] = None

CONF_RE = re.compile(r";\s*confidence:(\d+)\s*$", re.I)
VER_RE  = re.compile(r";\s*version:\\(\d+)\s*$", re.I)

def compile_pattern(pat: str) -> 'CompiledPattern':
    raw = pat
    conf = 50
    version_group = None
    mver = VER_RE.search(pat)
    if mver:
        try:
            version_group = int(mver.group(1))
        except ValueError:
            version_group = None
        pat = pat[:mver.start()]
    m = CONF_RE.search(pat)
    if m:
        conf = int(m.group(1))
        pat = pat[:m.start()]
    try:
        rx = re.compile(pat, re.I | re.S)
    except re.error:
        rx = re.compile(re.escape(pat), re.I | re.S)
    return CompiledPattern(raw=raw, regex=rx, confidence=conf, version_group=version_group)

@dataclass
class Evidence:
    field: str
    detail: str
    match: str
    confidence: int
    version: Optional[str] = None

@dataclass
class TechResult:
    name: str
    score: int = 0
    versions: Set[str] = field(default_factory=set)
    evidences: List[Evidence] = field(default_factory=list)

class WebTechMatcher:
    def __init__(self, dataset: Dict[str, Any]):
        self.dataset = dataset
        self.categories = dataset.get("categories", {})
        self.techs = dataset.get("technologies", {})

    def _match_headers(self, patterns: Dict[str, str], headers: Dict[str, str], res: 'TechResult'):
        for key, pat in patterns.items():
            cp = compile_pattern(pat)
            target_val = None
            for hname, hvalue in headers.items():
                if hname.lower() == key.lower():
                    target_val = hvalue
                    break
            if target_val is None and re.search(r"[^A-Za-z0-9\-]", key):
                for hname, hvalue in headers.items():
                    try:
                        if re.search(key, hname, re.I):
                            target_val = hvalue
                            break
                    except re.error:
                        pass
            if target_val is None:
                continue
            m = cp.regex.search(target_val or "")
            if m:
                version = None
                if cp.version_group is not None and cp.version_group <= (m.lastindex or 0):
                    version = m.group(cp.version_group)
                res.score += cp.confidence
                res.evidences.append(Evidence("headers", f"{key}", m.group(0)[:200], cp.confidence, version))
                if version:
                    res.versions.add(version)

    def _match_cookies(self, patterns: Dict[str, str], cookies: Dict[str, str], set_cookie_headers: List[str], res: 'TechResult'):
        candidates = dict(cookies)
        for sc in set_cookie_headers:
            parts = sc.split(";")[0].split("=", 1)
            if parts and parts[0]:
                cname = parts[0].strip()
                cval = parts[1].strip() if len(parts) > 1 else ""
                candidates.setdefault(cname, cval)
        for name_pat, val_pat in patterns.items():
            name_rx = compile_pattern(name_pat)
            for cname, cval in candidates.items():
                if name_rx.regex.search(cname):
                    val_rx = compile_pattern(val_pat) if isinstance(val_pat, str) else None
                    ok = True
                    if val_rx and val_pat not in ("", ".*", None):
                        if not val_rx.regex.search(cval or ""):
                            ok = False
                    if ok:
                        conf = (val_rx.confidence if val_rx else name_rx.confidence)
                        res.score += conf
                        res.evidences.append(Evidence("cookies", cname, (cval or "")[:200], conf, None))

    def _match_html(self, pat: str, html: str, res: 'TechResult'):
        cp = compile_pattern(pat)
        m = cp.regex.search(html or "")
        if m:
            version = None
            if cp.version_group is not None and cp.version_group <= (m.lastindex or 0):
                version = m.group(cp.version_group)
            res.score += cp.confidence
            res.evidences.append(Evidence("html", "html", m.group(0)[:200], cp.confidence, version))
            if version:
                res.versions.add(version)

    def _match_scripts(self, pats: List[str], script_srcs: List[str], res: 'TechResult'):
        for pat in pats:
            cp = compile_pattern(pat)
            for src in script_srcs:
                m = cp.regex.search(src)
                if m:
                    version = None
                    if cp.version_group is not None and cp.version_group <= (m.lastindex or 0):
                        version = m.group(cp.version_group)
                    res.score += cp.confidence
                    res.evidences.append(Evidence("scripts", src[:200], m.group(0)[:200], cp.confidence, version))
                    if version:
                        res.versions.add(version)

    def _match_dom(self, dom_rules: Dict[str, Any], soup: BeautifulSoup, res: 'TechResult'):
        for selector, rule in dom_rules.items():
            try:
                nodes = soup.select(selector)
            except Exception:
                continue
            if isinstance(rule, dict) and "exists" in rule and nodes:
                res.score += 40
                res.evidences.append(Evidence("dom", selector, "exists", 40, None))

    def _match_url(self, pat: str, url: str, res: 'TechResult'):
        cp = compile_pattern(pat)
        m = cp.regex.search(url or "")
        if m:
            version = None
            if cp.version_group is not None and cp.version_group <= (m.lastindex or 0):
                version = m.group(cp.version_group)
            res.score += cp.confidence
            res.evidences.append(Evidence("url", url[:200], m.group(0)[:200], cp.confidence, version))
            if version:
                res.versions.add(version)

    def _match_xhr(self, pat: str, html: str, res: 'TechResult'):
        cp = compile_pattern(pat)
        m = cp.regex.search(html or "")
        if m:
            res.score += cp.confidence
            res.evidences.append(Evidence("xhr", "html", m.group(0)[:200], cp.confidence, None))

    def _match_dns(self, rules: Dict[str, Any], hostname: str, res: 'TechResult'):
        if not DNS_AVAILABLE or not hostname:
            return
        for rtype, patterns in rules.items():
            rtype = rtype.upper()
            for pat in patterns:
                cp = compile_pattern(pat)
                try:
                    answers = dns.resolver.resolve(hostname, rtype)  # type: ignore
                except Exception:
                    continue
                for ans in answers:
                    s = str(ans.to_text())
                    if cp.regex.search(s):
                        res.score += cp.confidence
                        res.evidences.append(Evidence(f"dns:{rtype}", hostname, s[:200], cp.confidence, None))

    def analyze(self, target_url: str, dataset_path: Optional[str] = None,
                html_path: Optional[str] = None, timeout: float = 15.0,
                user_agent: str = DEFAULT_UA, follow_redirects: bool = True,
                do_dns: bool = False, dump: bool = False) -> Dict[str, Any]:

        html = ""
        final_url = target_url
        headers_ci = {}
        cookies = {}
        set_cookie_lines = []
        script_srcs: List[str] = []
        fetch_debug = {"headers": {}, "cookies": {}, "set_cookie": [], "script_srcs": [], "html_title": "", "html_len": 0}

        if html_path:
            with open(html_path, "r", encoding="utf-8", errors="ignore") as f:
                html = f.read()
            final_url = target_url
        else:
            sess = requests.Session()
            req_headers = {"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
            try:
                resp = sess.get(target_url, headers=req_headers, timeout=timeout, allow_redirects=follow_redirects)
                final_url = resp.url
                html = resp.text or ""
                headers_ci = {k.strip(): (v if isinstance(v, str) else str(v)) for k, v in resp.headers.items()}
                cookies = {c.name: c.value for c in resp.cookies}
                raw_set_cookie = resp.headers.get("Set-Cookie")
                if raw_set_cookie:
                    sc_parts = raw_set_cookie.split(", ")
                    set_cookie_lines = [p for p in sc_parts if "=" in p]
                fetch_debug["headers"] = dict(headers_ci)
                fetch_debug["cookies"] = dict(cookies)
                fetch_debug["set_cookie"] = list(set_cookie_lines)
            except RequestException as e:
                return {"error": f"Request failed: {e}", "url": target_url}

        try:
            soup = BeautifulSoup(html, "html.parser")
            title_tag = soup.title.string.strip() if soup.title and soup.title.string else ""
            fetch_debug["html_title"] = title_tag
            fetch_debug["html_len"] = len(html or "")
            script_srcs = [s.get("src") for s in soup.find_all("script") if s.get("src")]
        except Exception:
            pass

        try:
            from urllib.parse import urlparse
            hostname = urlparse(final_url).hostname or ""
        except Exception:
            hostname = ""

        results: Dict[str, TechResult] = {}
        for name, entry in self.techs.items():
            res = TechResult(name=name)
            if "headers" in entry and fetch_debug["headers"]:
                self._match_headers(entry["headers"], fetch_debug["headers"], res)
            if "cookies" in entry and (fetch_debug["cookies"] or fetch_debug["set_cookie"]):
                self._match_cookies(entry["cookies"], fetch_debug["cookies"], fetch_debug["set_cookie"], res)
            if "scripts" in entry and script_srcs:
                self._match_scripts(entry["scripts"], script_srcs, res)
            if "html" in entry and html:
                self._match_html(entry["html"], html, res)
            if "url" in entry and final_url:
                self._match_url(entry["url"], final_url, res)
            if "xhr" in entry and html:
                self._match_xhr(entry["xhr"], html, res)
            if "dns" in entry and do_dns and hostname:
                self._match_dns(entry["dns"], hostname, res)
            if res.score > 0:
                results[name] = res

        # implies/requirements/excludes omitted here for brevity in this pasted patch

        out = []
        for name, res in sorted(results.items(), key=lambda kv: (-kv[1].score, kv[0])):
            entry = self.techs.get(name, {})
            cat_ids = entry.get("cats", [])
            cat_names = [self.categories.get(str(cid), str(cid)) for cid in cat_ids]
            out.append({
                "name": name,
                "score": min(res.score, 100),
                "versions": sorted(list(v for v in res.versions if v)),
                "categories": cat_names,
                "saas": entry.get("saas"),
                "oss": entry.get("oss"),
                "website": entry.get("website"),
                "description": entry.get("description"),
                "evidence": [e.__dict__ for e in res.evidences],
                "source": "dataset"
            })

        return {
            "url": final_url,
            "debug": fetch_debug if dump else None,
            "technologies_detected": out,
            "counts": {"matched": len(out), "tested": len(self.techs)},
        }

def _parse_whatweb_json_text(txt: str):
    txt = txt.strip()
    if not txt:
        return None
    lines = [txt] if txt.startswith("{") else txt.splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and ("plugins" in obj or "http_status" in obj or "plugins_count" in obj):
                return obj
        except Exception:
            continue
    return None

def run_whatweb(url: str, whatweb_path: str = "whatweb", user_agent: Optional[str] = None,
                timeout: int = 15, aggression: Optional[int] = None):
    base_cmd = [whatweb_path, url, "--log-json=-"]
    if aggression is not None:
        base_cmd += ["-a", str(aggression)]
    if user_agent:
        base_cmd += ["-U", user_agent]
    try:
        proc = subprocess.run(base_cmd, capture_output=True, text=True, timeout=timeout)
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        obj = _parse_whatweb_json_text(out)
        if obj:
            return obj, None
        return None, "WhatWeb produced no parseable JSON output."
    except FileNotFoundError:
        return None, f"WhatWeb not found at path: {whatweb_path}"
    except subprocess.TimeoutExpired:
        return None, "WhatWeb timed out."
    except Exception as e:
        return None, f"WhatWeb error: {e}"

def _extract_whatweb_findings(obj: Dict[str, Any]):
    found = []
    plugins = obj.get("plugins") or {}
    if isinstance(plugins, dict):
        for pname, pdata in plugins.items():
            if isinstance(pdata, list):
                versions = sorted({str(i.get('version')) for i in pdata if isinstance(i, dict) and i.get('version')})
                info = "; ".join([str(i.get('string')) for i in pdata if isinstance(i, dict) and i.get('string')])
            else:
                versions, info = [], str(pdata)
            found.append((pname, versions, info))
    return found

def merge_whatweb_into_result(result: Dict[str, Any], ww_obj: Dict[str, Any]) -> Dict[str, Any]:
    present = {t.get("name","").lower() for t in result.get("technologies_detected", [])}
    for nm, versions, info in _extract_whatweb_findings(ww_obj):
        if nm.lower() in present:
            continue
        result["technologies_detected"].append({
            "name": nm, "score": 60, "versions": versions, "categories": [],
            "saas": None, "oss": None, "website": None,
            "description": info or None,
            "evidence": [{"field":"whatweb","detail":"plugin","match":info or "", "confidence":60, "version": (versions or [None])[0]}],
            "source": "whatweb"
        })
    result["whatweb_raw"] = ww_obj
    result["counts"]["matched"] = len(result.get("technologies_detected", []))
    return result

# Wappalyzer (robust)
def _get_wappalyzer_instance(update: bool = False):
    if not WAPPALYZER_AVAILABLE:
        return None, "python-Wappalyzer is not installed."
    try:
        if update:
            return PyWappalyzer.latest(update=True), None
        return PyWappalyzer.latest(), None
    except TypeError:
        try:
            w = PyWappalyzer.latest()
            if update:
                try:
                    url = "https://raw.githubusercontent.com/wappalyzer/wappalyzer/master/src/technologies.json"
                    r = requests.get(url, timeout=15); r.raise_for_status()
                    tech = r.json()
                    return PyWappalyzer(tech), None
                except Exception as e:
                    return w, f"Could not update fingerprints online ({e}); using bundled fingerprints."
            return w, None
        except Exception as e2:
            return None, f"Wappalyzer init failed: {e2}"
    except Exception as e:
        return None, f"Wappalyzer init error: {e}"

def run_wappalyzer(url: str, user_agent: Optional[str] = None, timeout: int = 15, update: bool = False):
    wapp, init_err = _get_wappalyzer_instance(update=update)
    if init_err and wapp is None:
        return None, init_err
    warn = init_err
    try:
        page = PyWebPage.new_from_url(url, headers={"User-Agent": user_agent or DEFAULT_UA}, timeout=timeout)
        if hasattr(wapp, "analyze_with_versions_and_categories"):
            data = wapp.analyze_with_versions_and_categories(page)
            result = {"results": data}
        elif hasattr(wapp, "analyze_with_versions"):
            versions_map = wapp.analyze_with_versions(page)
            data = {app: {"versions": list(versions_map.get(app) or []), "categories": []} for app in versions_map}
            result = {"results": data}
        else:
            apps = wapp.analyze(page)
            data = {app: {"versions": [], "categories": []} for app in apps}
            result = {"results": data}
        if warn:
            result["warning"] = warn
        return result, None
    except Exception as e:
        return None, f"Wappalyzer error: {e}"

def merge_wappalyzer_into_result(result: Dict[str, Any], wz_obj: Dict[str, Any]) -> Dict[str, Any]:
    payload = wz_obj.get("results") or {}
    present = {t.get("name","").lower() for t in result.get("technologies_detected", [])}
    for name, info in payload.items():
        if name.lower() in present:
            continue
        versions = info.get("versions") or []
        cats = info.get("categories") or []
        result["technologies_detected"].append({
            "name": name, "score": 65, "versions": versions,
            "categories": cats, "saas": None, "oss": None, "website": None,
            "description": None,
            "evidence": [{"field":"wappalyzer","detail":"python-Wappalyzer","match":", ".join(cats)[:120], "confidence":65, "version": (versions or [None])[0]}],
            "source": "wappalyzer"
        })
    result["wappalyzer_raw"] = wz_obj
    result["counts"]["matched"] = len(result.get("technologies_detected", []))
    return result

def main():
    p = argparse.ArgumentParser(description="Web technology matcher using dataset + WhatWeb + python-Wappalyzer")
    p.add_argument("target", help="Target URL, e.g. https://example.com")
    p.add_argument("--dataset", default="web_tech_dataset.json", help="Path to dataset JSON")
    p.add_argument("--html", dest="html_path", help="Analyze from a saved HTML file instead of fetching")
    p.add_argument("--dns", action="store_true", help="Enable optional DNS checks (requires dnspython)")
    p.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout seconds")
    p.add_argument("--user-agent", default=DEFAULT_UA, help="Custom User-Agent")
    p.add_argument("--no-redirects", action="store_true", help="Do not follow redirects")
    p.add_argument("--top", type=int, default=25, help="Show top N technologies")
    p.add_argument("--json", action="store_true", help="Print JSON output only")
    p.add_argument("--dump", action="store_true", help="Dump fetched headers/cookies/script srcs for debugging")
    p.add_argument("--whatweb", action="store_true", help="Run WhatWeb and merge its detections")
    p.add_argument("--whatweb-path", default="whatweb", help="Path to the WhatWeb executable")
    p.add_argument("--whatweb-aggr", type=int, help="WhatWeb aggression level (0–4)")
    p.add_argument("--wappalyzer", action="store_true", help="Run python-Wappalyzer and merge its detections")
    p.add_argument("--wappalyzer-update", action="store_true", help="Try to refresh Wappalyzer fingerprints before analyzing")
    args = p.parse_args()

    try:
        with open(args.dataset, "r", encoding="utf-8") as f:
            dataset = json.load(f)
    except Exception as e:
        print(f"Failed to load dataset '{args.dataset}': {e}", file=sys.stderr); sys.exit(2)

    matcher = WebTechMatcher(dataset)
    result = matcher.analyze(
        target_url=args.target,
        dataset_path=args.dataset,
        html_path=args.html_path,
        timeout=args.timeout,
        user_agent=args.user_agent,
        follow_redirects=not args.no_redirects,
        do_dns=args.dns,
        dump=args.dump,
    )

    if args.whatweb:
        ww_obj, ww_err = run_whatweb(args.target, args.whatweb_path, args.user_agent, int(max(5, args.timeout)), args.whatweb_aggr)
        if ww_err: result["whatweb_error"] = ww_err
        if ww_obj: result = merge_whatweb_into_result(result, ww_obj)

    if args.wappalyzer:
        wz_obj, wz_err = run_wappalyzer(args.target, args.user_agent, int(max(5, args.timeout)), args.wappalyzer_update)
        if wz_err: result["wappalyzer_error"] = wz_err
        if wz_obj: result = merge_wappalyzer_into_result(result, wz_obj)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False)); return

    if "error" in result:
        print(f"[ERROR] {result['error']}", file=sys.stderr); sys.exit(1)

    print(f"\nURL: {result['url']}")
    print(f"Detected {result['counts']['matched']} technologies (tested {result['counts']['tested']}).\n")

if __name__ == "__main__":
    main()
