#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import time
import hashlib
import logging
import argparse
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse

import yaml
import requests
from bs4 import BeautifulSoup
from dateutil import parser as dtparser
from tqdm import tqdm

LOG = logging.getLogger("fetch-reports")

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def ts_utc() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"

def load_yaml(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def save_json(path: Path, obj):
    # 親ディレクトリが無いと FileNotFoundError になるため必ず作成
    ensure_dir(path.parent)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def read_json(path: Path, default):
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return default

def make_session(defaults: dict):
    s = requests.Session()
    headers = {
        "User-Agent": defaults.get("user_agent", "ThreatReportFetcher/1.0"),
        "Accept": "*/*",
    }
    # 追加ヘッダ（SecretsからJSONで渡せる）
    extra = os.environ.get("EXTRA_HEADERS_JSON")
    if extra:
        try:
            headers.update(json.loads(extra))
        except Exception:
            LOG.warning("Invalid EXTRA_HEADERS_JSON; ignored.")
    s.headers.update(headers)
    s.timeout = defaults.get("timeout", 30)
    return s

def request_with_retries(session: requests.Session, url: str, retries=3, timeout=30):
    last = None
    for i in range(retries):
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
            if resp.status_code == 200:
                return resp
            last = resp
            time.sleep(2 * (i + 1))
        except requests.RequestException as e:
            last = e
            time.sleep(2 * (i + 1))
    if isinstance(last, requests.Response):
        raise RuntimeError(f"Failed {url}: HTTP {last.status_code}")
    raise RuntimeError(f"Failed {url}: {last}")

def sanitize_filename(name: str) -> str:
    # URL末尾やTitleから安全なファイル名を生成
    name = re.sub(r"[^\w\-.]+", "_", name, flags=re.UNICODE)
    return name.strip("._") or "file"

def guess_ext_from_ct(resp: requests.Response, url: str) -> str:
    ct = resp.headers.get("Content-Type", "").lower()
    if "pdf" in ct: return ".pdf"
    if "html" in ct: return ".html"
    # URL拡張子から推定
    path = urlparse(url).path
    if path.endswith(".pdf"): return ".pdf"
    if path.endswith(".html") or path.endswith(".htm"): return ".html"
    return ".bin"

def extract_links(html: str, base_url: str, selector: str):
    soup = BeautifulSoup(html, "lxml")
    # 単純化：selectorはa要素に対するCSS（例：a[href]）
    matches = soup.select(selector or "a[href]")
    out = []
    for a in matches:
        href = a.get("href")
        text = a.get_text(" ", strip=True)[:300]
        if not href:
            continue
        abs_url = urljoin(base_url, href)
        out.append((text, abs_url))
    return out

def pick_by_regex(pairs, regex: str):
    pat = re.compile(regex, re.IGNORECASE)
    picked = []
    for text, url in pairs:
        s = f"{text} {url}"
        if pat.search(s):
            picked.append((text, url))
    return picked

def save_binary(path: Path, content: bytes):
    ensure_dir(path.parent)
    with open(path, "wb") as f:
        f.write(content)

def update_index(index_path: Path, records: list):
    index = read_json(index_path, default={"updated_at": ts_utc(), "items": []})
    # 既存アイテムをURLキーで辞書化
    by_url = {item["url"]: item for item in index["items"]}
    for r in records:
        by_url[r["url"]] = r
    index["items"] = sorted(by_url.values(), key=lambda x: (x.get("published_at") or "", x["url"]), reverse=True)
    index["updated_at"] = ts_utc()
    save_json(index_path, index)
    return index

def trim_keep(out_dir: Path, keep: int):
    if keep <= 0: return
    files = sorted(out_dir.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    for f in files[keep:]:
        try: f.unlink()
        except Exception: pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    cfg = load_yaml(Path(args.config))
    defaults = cfg.get("defaults", {})
    dest_root = cfg.get("dest_root", "security-reports")
    sources = cfg.get("sources", [])

    session = make_session(defaults)
    records_for_index = []

    out_root = Path(args.out)
    ensure_dir(out_root)
    # まだ1件も落ちなくても index.json を書けるように先に作成
    ensure_dir(out_root / dest_root

    for src in sources:
        sid = src["id"]
        name = src.get("name", sid)
        typ = src.get("type", "list_latest")
        start_url = src["start_url"]
        selector = src.get("selector", "a[href]")
        regex = src.get("regex", "")
        keep = int(src.get("keep", 5))
        out_dir = out_root / dest_root / src.get("out_dir", sid)

        LOG.info(f"[{sid}] Fetching from {start_url} ({typ})")
        try:
            resp = request_with_retries(session, start_url,
                                        retries=defaults.get("retries", 3),
                                        timeout=defaults.get("timeout", 30))
            base_html = resp.text
            candidates = []

            if typ in ("list_latest", "direct"):
                pairs = extract_links(base_html, start_url, selector)
                if regex:
                    pairs = pick_by_regex(pairs, regex)
                # direct の場合でも複数ヒットしうるため上限をkeepに揃える
                candidates = pairs[:max(keep, 1)]

            elif typ == "rss":
                # RSS/Atom対応（必要なら feedparser 追加して拡張可能）
                raise NotImplementedError("rss type is not implemented in this minimal sample.")

            else:
                raise ValueError(f"Unknown type: {typ}")

            # ダウンロード
            downloaded = 0
            for text, url in candidates:
                try:
                    doc = request_with_retries(session, url,
                                               retries=defaults.get("retries", 3),
                                               timeout=defaults.get("timeout", 30))
                    ext = guess_ext_from_ct(doc, url)
                    # ファイル名：YYYY-..._sanitized.ext の形式を目指す（DateはHTTPヘッダ/推定）
                    pub_at = None
                    http_date = doc.headers.get("Last-Modified") or doc.headers.get("Date")
                    if http_date:
                        try:
                            pub_at = dtparser.parse(http_date).date().isoformat()
                        except Exception:
                            pub_at = None

                    base_name = sanitize_filename((pub_at or "") + "_" + (Path(urlparse(url).path).name or text[:50]))
                    if not base_name.lower().endswith(ext):
                        base_name += ext

                    save_path = out_dir / base_name
                    if save_path.exists():
                        # 既存ならスキップ（軽量化）
                        LOG.info(f"  exists: {save_path}")
                    else:
                        save_binary(save_path, doc.content)
                        LOG.info(f"  saved:  {save_path}")
                        downloaded += 1

                    rec = {
                        "source_id": sid,
                        "source_name": name,
                        "title": text,
                        "url": url,
                        "saved_path": str(save_path.as_posix()),
                        "sha256": sha256_bytes(doc.content),
                        "content_type": doc.headers.get("Content-Type", ""),
                        "published_at": pub_at,
                        "fetched_at": ts_utc(),
                    }
                    records_for_index.append(rec)

                except Exception as e:
                    LOG.warning(f"  skip {url}: {e}")

            # 保存上限に合わせて古いファイルを削除（データ量制御）
            trim_keep(out_dir, keep=keep)

            LOG.info(f"[{sid}] done (downloaded={downloaded})")

        except Exception as e:
            LOG.error(f"[{sid}] failed: {e}")

    # 目録更新（ルートに index.json を作る）
    index_path = out_root / dest_root / "index.json"
    index = update_index(index_path, records_for_index)
    LOG.info(f"Index updated: {index_path} (items={len(index.get('items', []))})")

if __name__ == "__main__":
    main()
