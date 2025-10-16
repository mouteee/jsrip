"""
JS Analyzer for jsrip
- Beautifies JS (optional)
- Dedupes files by content before scanning (to save time & reduce dup findings)
- Finds secrets with curated regex patterns + entropy/hash/base64 context filters
- Extracts endpoints and filters to in-scope by default (can include external with a flag)
- Outputs structures compatible with jsrip's reporter
"""

import os
import re
import math
import hashlib
from urllib.parse import urlparse
from pathlib import Path

try:
    import jsbeautifier
except Exception:
    jsbeautifier = None

from .patterns import patterns


def _registrable(host: str) -> str:
    if not host:
        return ""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


class JSAnalyzer:
    # Regex patterns for context filtering
    B64_IMAGE_RE = re.compile(
        r'data:image\/[a-zA-Z0-9.+-]+;base64,[A-Za-z0-9+/=\s]{100,}',
        re.IGNORECASE
    )
    GENERIC_B64_BLOB_RE = re.compile(
        r'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{400,}={0,2}(?![A-Za-z0-9+/=])'
    )

    def __init__(
        self,
        output_dir,
        beautify=True,
        verbose=False,
        base_reg=None,
        include_external_endpoints=False,
        entropy_threshold=2.5,
        min_secret_length=8,
    ):
        """
        Args:
            output_dir: jsrip run directory
            beautify: prettify JS before scanning
            verbose: print progress
            base_reg: registrable domain (e.g., example.com) to scope endpoints
            include_external_endpoints: do not filter endpoints to base_reg
            entropy_threshold: minimum Shannon entropy to accept generic-looking secrets
            min_secret_length: minimum secret length
        """
        self.output_dir = Path(output_dir)
        self.js_dir = self.output_dir / "javascript"
        self.js_dir.mkdir(parents=True, exist_ok=True)

        self.beautify = beautify and (jsbeautifier is not None)
        self.verbose = verbose
        self.base_reg = base_reg
        self.include_external_endpoints = include_external_endpoints
        self.entropy_threshold = float(entropy_threshold)
        self.min_secret_length = int(min_secret_length)

    # -------------------- Public API --------------------

    def analyze_files(self, js_files_dict):
        """
        Args:
            js_files_dict: list or dict of JS file info with 'filepath' keys
        Returns:
            dict: {'secrets': [...], 'endpoints': [...]}
        """
        results = {'secrets': [], 'endpoints': []}

        # Normalize to list of paths
        if isinstance(js_files_dict, dict):
            js_files = [v for v in js_files_dict.values() if isinstance(v, dict)]
        else:
            js_files = [v for v in (js_files_dict or []) if isinstance(v, dict) or isinstance(v, str)]

        # Build list of actual file paths
        file_paths = []
        for item in js_files:
            if isinstance(item, dict):
                fp = item.get('filepath') or item.get('path')
            else:
                fp = str(item)
            if fp and os.path.exists(fp):
                file_paths.append(fp)

        # Deduplicate by content hash (keep first path encountered)
        unique_files = self._unique_js_by_content(file_paths)

        seen_secrets = {}   # (type, value) -> finding
        seen_endpoints = set()

        for fp in unique_files:
            try:
                with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception:
                continue

            # Beautify (best-effort)
            if self.beautify:
                try:
                    content = jsbeautifier.beautify(content)
                    # persist pretty (helps manual review)
                    try:
                        with open(fp, 'w', encoding='utf-8') as wf:
                            wf.write(content)
                    except Exception:
                        pass
                except Exception:
                    pass

            cleaned = self._strip_base64_blobs(content)

            # ---- secrets
            file_secrets = self._find_secrets(cleaned, fp)
            for s in file_secrets:
                key = (s['type'], s['value'])
                if key not in seen_secrets:
                    seen_secrets[key] = s
                    results['secrets'].append(s)
                else:
                    existing = seen_secrets[key]
                    existing.setdefault('also_in', []).append(s['file'])

            # ---- endpoints
            file_endpoints = self._find_endpoints(content)
            for ep in file_endpoints:
                if ep in seen_endpoints:
                    continue
                seen_endpoints.add(ep)
                results['endpoints'].append({
                    'url': ep,
                    'source_file': os.path.basename(fp)
                })

        return results

    # -------------------- Helpers --------------------

    def _unique_js_by_content(self, paths):
        """Return unique file paths by content hash; keep first occurrence."""
        seen = set()
        uniq = []
        for fp in paths:
            try:
                with open(fp, 'rb') as f:
                    data = f.read()
                h = hashlib.sha256(data).hexdigest()
                if h in seen:
                    continue
                seen.add(h)
                uniq.append(fp)
            except Exception:
                continue
        return uniq

    def _strip_base64_blobs(self, text):
        text = self.B64_IMAGE_RE.sub('', text)
        text = self.GENERIC_B64_BLOB_RE.sub('', text)
        return text

    def _find_secrets(self, content, filepath):
        findings = []
        local_seen = set()
        filename = os.path.basename(filepath)

        for secret_type, pattern in patterns.items():
            try:
                regex = re.compile(pattern, re.IGNORECASE) if isinstance(pattern, str) else pattern
            except Exception:
                regex = pattern

            for match in regex.finditer(content):
                secret_value = self._normalize_secret(match.group())

                # length sanity
                if len(secret_value) < self.min_secret_length or len(secret_value) > 512:
                    continue

                # local context (trimmed in report)
                start = max(0, match.start() - 120)
                end = min(len(content), match.end() + 120)
                context = content[start:end]

                # skip obvious base64 image contexts
                if self._is_base64_image_context(context) and len(secret_value) > 24:
                    continue

                # drop obvious hashes unless pattern expects them
                if self._is_hash(secret_value):
                    if not any(k in secret_type.lower() for k in ('md5', 'sha', 'hash', 'checksum')):
                        continue

                # entropy gating for generic credentials
                entropy = self._calculate_entropy(secret_value)
                if entropy < self.entropy_threshold:
                    if not any(k in secret_type.lower() for k in ('cookie', 'token', 'secret', 'key',
                                                                  'password', 'auth', 'bearer', 'apikey')):
                        continue

                dedup_key = (secret_type, secret_value)
                if dedup_key in local_seen:
                    continue
                local_seen.add(dedup_key)

                confidence = 'high' if entropy >= 3.3 else 'medium'

                findings.append({
                    'type': secret_type,
                    'value': secret_value,
                    'file': filename,
                    'context': context[:300],
                    'entropy': round(entropy, 2),
                    'confidence': confidence
                })

        return findings

    def _find_endpoints(self, content):
        endpoints = set()

        endpoint_patterns = [
            r'["\']/(api|v\d+|rest|graphql)/[a-zA-Z0-9/_-]+["\']',
            r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9._~:/?#[\]@!$&\'()*+,;=-]*)?',
            r'["\'][a-zA-Z0-9/_-]+\?[a-zA-Z0-9=&_-]+["\']',
        ]

        for pattern in endpoint_patterns:
            try:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    endpoint = match.group().strip('\'"')
                    if self._is_valid_endpoint(endpoint):
                        endpoints.add(endpoint)
            except Exception:
                pass

        return list(endpoints)

    def _is_valid_endpoint(self, endpoint):
        # quick rejects
        if len(endpoint) < 8 or len(endpoint) > 500:
            return False

        # remove obvious doc/license/tracker links typically embedded in libs
        lower = endpoint.lower()
        if any(s in lower for s in (
            "license", "github.com/", "opensource.org", "cookiesandyou.com", "creativecommons.org"
        )):
            return False

        # optional in-scope filtering
        if not self.include_external_endpoints and endpoint.startswith("http"):
            try:
                host = urlparse(endpoint).hostname or ""
            except Exception:
                host = ""
            if self.base_reg and _registrable(host) != self.base_reg:
                return False

        # common false positives
        false_pos = (
            "http://www.w3.org",
            "http://example.com", "https://example.com",
            "http://localhost", "https://localhost",
            "/path/to/", "/example/"
        )
        if any(endpoint.startswith(fp) for fp in false_pos):
            return False

        return True

    def _is_base64_image_context(self, context):
        cl = context.lower()
        return 'data:image' in cl or 'svg+xml;base64' in cl

    def _is_hash(self, value):
        return bool(re.fullmatch(r'[A-Fa-f0-9]{32}', value)) or \
               bool(re.fullmatch(r'[A-Fa-f0-9]{40}', value)) or \
               bool(re.fullmatch(r'[A-Fa-f0-9]{64}', value))

    def _normalize_secret(self, value):
        return value.strip().strip('\'"').strip()

    def _calculate_entropy(self, s):
        if not s:
            return 0.0
        freq = {}
        for ch in s:
            freq[ch] = freq.get(ch, 0) + 1
        ent = 0.0
        n = len(s)
        for c in freq.values():
            p = c / n
            ent -= p * math.log2(p)
        return ent