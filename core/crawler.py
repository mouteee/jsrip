"""
Playwright-based crawler for jsrip, adapted and expanded for better coverage.
- Same-registrable-domain scope
- Discovers external + inline JS via network hooks & DOM
- Light interactions (scroll + safe anchor clicks) to surface lazy content
- Breadth-first queue with concurrency for deeper coverage
"""

import os
import re
import asyncio
import hashlib
import random
from urllib.parse import urlparse, urljoin
from collections import deque, defaultdict
from pathlib import Path

from playwright.async_api import async_playwright
from playwright._impl._errors import TimeoutError as PWTimeoutError

try:
    import tldextract
except Exception:
    tldextract = None

try:
    import jsbeautifier
except Exception:
    jsbeautifier = None

JS_CT_HINTS = (
    "application/javascript",
    "application/x-javascript",
    "text/javascript",
    "text/ecmascript",
    "application/ecmascript",
    "application/x-ecmascript",
    "text/js",
)

VENDOR_HOST_DENY = {
    "www.google-analytics.com",
    "www.googletagmanager.com",
    "connect.facebook.net",
    "static.cloudflareinsights.com",
    "challenges.cloudflare.com",
    "www.recaptcha.net", "www.google.com",
    "bat.bing.com",
}

SMAP_RE = re.compile(r'^\s*//#\s*sourceMappingURL=([^\s]+)\s*$', re.MULTILINE)


def registrable_domain(host: str) -> str:
    if not host:
        return ""
    if tldextract:
        try:
            ext = tldextract.extract(host)
            return f"{ext.domain}.{ext.suffix}" if ext.suffix else host
        except Exception:
            pass
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def in_scope(url: str, base_reg: str) -> bool:
    try:
        u = urlparse(url)
        if not u.scheme.startswith("http"):
            return False
        host = u.hostname or ""
        return registrable_domain(host) == base_reg
    except Exception:
        return False


def safe_filename_from_url(u: str, fallback_hash: str, suffix: str) -> str:
    p = urlparse(u)
    name = os.path.basename(p.path) or ""
    name = name.split("?")[0]
    if not name:
        name = f"{fallback_hash}{suffix}"
    name = re.sub(r'[^A-Za-z0-9._-]', '_', name)
    return name[:180]


class PlaywrightCrawler:
    """
    Public API:
        await PlaywrightCrawler(config, logger).crawl_urls(urls) -> list[dict]
    Returns list of JS file records:
        {url, filepath, filename, size, sha256, source_page}
    """

    def __init__(self, config: dict, logger):
        self.config = config
        self.logger = logger

        # IO
        self.output_dir = Path(config['output_dir'])
        self.js_dir = self.output_dir / "javascript"
        self.maps_dir = self.output_dir / "sourcemaps"
        self.meta_dir = self.output_dir / "playwright" / "meta"
        for d in (self.js_dir, self.maps_dir, self.meta_dir):
            d.mkdir(parents=True, exist_ok=True)

        # Settings
        self.headless = bool(config.get("headless", True))
        self.max_pages = int(config.get("max_pages", 500))
        self.max_depth = int(config.get("max_depth", 2))
        self.user_agent = config.get("user_agent") or "jsrip/1.0"
        self.timeout_ms = int(config.get("timeout", 30)) * 1000
        self.enable_beautify = bool(config.get("beautify", True))
        self.enable_interactions = bool(config.get("enable_interactions", True))
        self.max_concurrency = int(config.get("max_concurrency", 4))

        # State
        self.base_reg = None
        self.visited_pages = set()
        self.downloaded_hashes = set()
        self.js_files = []
        self.all_endpoints = defaultdict(set)
        self.inline_counter = 0

    async def crawl_urls(self, urls):
        seeds = [u for u in (urls or []) if u.startswith(("http://", "https://"))]
        if not seeds:
            self.logger.warning("No valid HTTP(S) URLs to crawl.")
            return []

        first_host = urlparse(seeds[0]).hostname or ""
        self.base_reg = registrable_domain(first_host)

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(
                    headless=self.headless,
                    args=["--disable-web-security", "--no-sandbox", "--disable-dev-shm-usage"]
                )

                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent=self.user_agent,
                    java_script_enabled=True,
                    bypass_csp=True,
                    extra_http_headers=self.config.get("headers") or {},
                    viewport={'width': 1366, 'height': 768},
                )

                if self.config.get("cookies"):
                    try:
                        await context.add_cookies(self.config["cookies"])
                    except Exception as e:
                        self.logger.debug(f"Failed to add cookies: {e}")

                try:
                    context.set_default_timeout(self.timeout_ms)
                except Exception:
                    pass

                # Queue + workers for breadth-first crawl
                q = asyncio.Queue()
                for u in seeds:
                    await q.put((u, 0))

                async def worker():
                    while not q.empty() and len(self.visited_pages) < self.max_pages:
                        url, depth = await q.get()
                        try:
                            await self._visit(context, url, depth, q)
                        except Exception as e:
                            self.logger.debug(f"Visit error {url}: {e}")
                        finally:
                            q.task_done()

                tasks = [asyncio.create_task(worker()) for _ in range(self.max_concurrency)]
                await q.join()
                for t in tasks:
                    t.cancel()

                await context.close()
                await browser.close()

        except Exception as e:
            self.logger.warning(f"Crawler error: {e}")

        self.logger.info(f"Crawling complete. Found {len(self.js_files)} JavaScript files")
        return self.js_files

    async def _visit(self, context, url: str, depth: int, q: asyncio.Queue):
        if depth > self.max_depth:
            return
        if url in self.visited_pages:
            return
        if len(self.visited_pages) >= self.max_pages:
            return
        if not in_scope(url, self.base_reg):
            return

        self.visited_pages.add(url)
        self.logger.info(f"Crawling: {url} (depth: {depth})")

        page = await context.new_page()
        page.on("response", lambda resp: asyncio.create_task(self._on_response(resp)))
        page.on("request", lambda req: self._on_request(req))

        try:
            page.set_default_navigation_timeout(self.timeout_ms)
            page.set_default_timeout(self.timeout_ms)
        except Exception:
            pass

        waits = ["networkidle", "load", "domcontentloaded", "commit"]

        async def _nav_once():
            last_exc = None
            for w in waits:
                try:
                    await page.goto(url, wait_until=w, timeout=self.timeout_ms)
                    if w == "commit":
                        try:
                            await page.wait_for_selector("body", timeout=3000)
                        except Exception:
                            pass
                    return
                except PWTimeoutError as te:
                    last_exc = te
                except Exception as e:
                    last_exc = e
            if last_exc:
                raise last_exc

        try:
            await _nav_once()
        except Exception as nav_exc:
            self.logger.debug(f"Nav failed {url}: {nav_exc}")
            await page.close()
            return

        # Light settle & optional interactions
        try:
            await page.wait_for_load_state("networkidle", timeout=1500)
        except Exception:
            pass

        if self.enable_interactions:
            await self._interact(page)

        # Extract and schedule
        links = await self._extract_links(page, base=url)
        scripts = await self._extract_script_tags(page, base=url)

        for l in links:
            if in_scope(l, self.base_reg) and l not in self.visited_pages:
                await q.put((l, depth + 1))

        for s in scripts:
            if in_scope(s, self.base_reg):
                # Response hook will save actual bodies when loaded
                pass

        await self._save_inline_scripts(page, source_url=url)
        await page.close()

    async def _interact(self, page):
        # gentle scroll
        try:
            for _ in range(2):
                await page.mouse.wheel(0, 1200)
                await asyncio.sleep(0.4)
        except Exception:
            pass

        # click a few visible anchors safely
        try:
            anchors = await page.locator("a:visible").all()
        except Exception:
            anchors = []
        for a in anchors[:12]:
            try:
                txt = (await a.inner_text(timeout=800)).lower() if await a.is_visible(timeout=800) else ""
                href = await a.get_attribute("href") or ""
                if any(b in (txt + href).lower() for b in ("logout", "signout", "delete", "remove")):
                    continue
                await a.click(timeout=800)
                try:
                    await page.wait_for_load_state("networkidle", timeout=1000)
                except Exception:
                    pass
            except Exception:
                pass

    def _on_request(self, req):
        try:
            url = req.url or ""
            if not in_scope(url, self.base_reg):
                return
            host = (urlparse(url).hostname or "").lower()
            if host in VENDOR_HOST_DENY:
                return
            rtype = (req.resource_type or "").lower()
            if rtype in ("xhr", "fetch"):
                self.all_endpoints["api"].add(url)
            elif rtype == "websocket":
                self.all_endpoints["websocket"].add(url)
        except Exception:
            pass

    async def _on_response(self, resp):
        try:
            url = resp.url
            status = resp.status
            ct = (resp.headers.get("content-type") or "").lower()
            if not in_scope(url, self.base_reg):
                return
            host = (urlparse(url).hostname or "").lower()
            if host in VENDOR_HOST_DENY:
                return
            if status < 200 or status >= 300:
                return
            path_is_js = urlparse(url).path.lower().endswith((".js", ".mjs", ".cjs"))
            if path_is_js or any(h in ct for h in JS_CT_HINTS):
                await self._save_js(url, resp)
        except Exception:
            pass

    async def _save_js(self, js_url: str, resp):
        try:
            body = await resp.body()
        except Exception:
            return

        sha = hashlib.sha256(body).hexdigest()
        if sha in self.downloaded_hashes:
            return
        self.downloaded_hashes.add(sha)

        fname = safe_filename_from_url(js_url, sha, ".js")
        fpath = self.js_dir / fname

        source_page = ""
        try:
            frame = resp.request.frame
            if frame and frame.url:
                source_page = frame.url
        except Exception:
            pass

        try:
            txt = body.decode("utf-8", errors="ignore")
            if self.enable_beautify and jsbeautifier:
                txt = jsbeautifier.beautify(txt)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(txt)
        except Exception:
            with open(fpath, "wb") as f:
                f.write(body)

        self.js_files.append({
            "url": js_url,
            "filepath": str(fpath),
            "filename": fpath.name,
            "size": len(body),
            "sha256": sha,
            "source_page": source_page,
        })

        # sourcemap best-effort
        try:
            sm_hdr = resp.headers.get("sourcemap") or resp.headers.get("x-sourcemap")
            sm_url = None
            if sm_hdr:
                sm_url = urljoin(js_url, sm_hdr)
            else:
                try:
                    txt = body.decode("utf-8", errors="ignore")
                    m = SMAP_RE.search(txt)
                    if m:
                        sm_url = urljoin(js_url, m.group(1).strip())
                except Exception:
                    pass
            # (optional) download sm_url later if desired
        except Exception:
            pass

    async def _save_inline_scripts(self, page, source_url: str):
        try:
            codes = await page.eval_on_selector_all("script:not([src])", "els => els.map(e => e.textContent || '')")
        except Exception:
            codes = []

        for code in codes:
            code = (code or "").strip()
            if not code:
                continue
            sha = hashlib.sha256(code.encode("utf-8", errors="ignore")).hexdigest()
            if sha in self.downloaded_hashes:
                continue
            self.downloaded_hashes.add(sha)

            self.inline_counter += 1
            fname = f"inline_{self.inline_counter}_{sha[:8]}.js"
            fpath = self.js_dir / fname
            try:
                txt = code
                if self.enable_beautify and jsbeautifier:
                    txt = jsbeautifier.beautify(code)
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(txt)
            except Exception:
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(code)

            self.js_files.append({
                "url": f"inline:{source_url}#{self.inline_counter}",
                "filepath": str(fpath),
                "filename": fpath.name,
                "size": len(code.encode("utf-8", errors="ignore")),
                "sha256": sha,
                "source_page": source_url,
            })

    async def _extract_links(self, page, base: str):
        links = set()
        try:
            hrefs = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.getAttribute('href'))")
            actions = await page.eval_on_selector_all("form[action]", "els => els.map(e => e.getAttribute('action'))")
            for a in actions:
                if not a:
                    continue
                links.add(urljoin(base, a))
            for h in hrefs:
                if not h:
                    continue
                u = urljoin(base, h)
                if u.startswith("http"):
                    host = (urlparse(u).hostname or "").lower()
                    if host in VENDOR_HOST_DENY:
                        continue
                    links.add(u.split('#')[0])
        except Exception:
            pass
        return [u for u in links if in_scope(u, self.base_reg)]

    async def _extract_script_tags(self, page, base: str):
        urls = set()
        try:
            srcs = await page.eval_on_selector_all("script[src]", "els => els.map(e => e.getAttribute('src'))")
            for s in srcs:
                if not s:
                    continue
                u = urljoin(base, s)
                if u.startswith("http"):
                    host = (urlparse(u).hostname or "").lower()
                    if host in VENDOR_HOST_DENY:
                        continue
                    urls.add(u.split('#')[0])
        except Exception:
            pass
        return [u for u in urls if in_scope(u, self.base_reg)]