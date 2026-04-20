"""
Core functionality for SIPG (Shodan IP Grabber).
"""

import time
import os
import threading
import ipaddress
import re
import json
import csv
import html as html_module
from typing import List, Optional, Iterator, Dict, Any, Set
from urllib.parse import quote_plus, unquote
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from .config import Config


class ShodanAPIError(Exception):
    """Exception raised for Shodan API errors."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class ShodanIPGrabber:
    """Main class for Shodan IP grabbing functionality."""
    
    DETAIL_FIELD_ALIASES: Dict[str, str] = {
        "ip": "ip_str",
        "ip_str": "ip_str",
        "port": "port",
        "ports": "ports",
        "transport": "transport",
        "org": "org",
        "asn": "asn",
        "isp": "isp",
        "city": "city",
        "country": "country",
        "location": "location",
        "hostnames": "hostnames",
        "domains": "domains",
        "product": "product",
        "os": "os",
        "timestamp": "timestamp",
        "vulns": "vulns",
        "vuln_count": "vuln_count",
    }
    DEFAULT_TABLE_FIELDS: List[str] = [
        "ip",
        "port",
        "transport",
        "org",
        "asn",
        "isp",
        "location",
        "hostnames",
        "domains",
        "product",
        "os",
        "timestamp",
        "vuln_count",
    ]
    DEFAULT_DETAIL_CSV_FIELDS: List[str] = [
        "ip",
        "port",
        "transport",
        "org",
        "asn",
        "isp",
        "city",
        "country",
        "hostnames",
        "domains",
        "product",
        "os",
        "timestamp",
    ]

    def __init__(
        self,
        config: Optional[Config] = None,
        api_min_interval: Optional[float] = None,
    ):
        """Initialize the Shodan IP Grabber.
        
        Args:
            config: Configuration object. If None, creates a new one.
            api_min_interval: Minimum seconds between api.shodan.io requests (0 = no cap).
                Default: 1.0, or SIPG_API_MIN_INTERVAL env, or override here.
        """
        self.config = config or Config()
        self.console = Console()
        self.session = requests.Session()
        self._api_min_interval = self._resolve_api_min_interval(api_min_interval)
        self._api_lock = threading.Lock()
        self._last_api_monotonic = 0.0
        # Browser-like headers: Shodan facet HTML is easier to fetch reliably than with a bare bot UA.
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }
        )

    @staticmethod
    def _resolve_api_min_interval(override: Optional[float]) -> float:
        if override is not None:
            return max(0.0, float(override))
        raw = os.environ.get("SIPG_API_MIN_INTERVAL", "").strip()
        if raw:
            try:
                return max(0.0, float(raw))
            except ValueError:
                pass
        return 1.0

    def _throttle_shodan_api(self) -> None:
        """Space out api.shodan.io calls (thread-safe)."""
        if self._api_min_interval <= 0:
            return
        with self._api_lock:
            now = time.monotonic()
            gap = self._api_min_interval - (now - self._last_api_monotonic)
            if gap > 0:
                time.sleep(gap)
            self._last_api_monotonic = time.monotonic()

    @staticmethod
    def _retry_after_wait(response: requests.Response, attempt: int) -> float:
        """Seconds to wait after 429/503; honors Retry-After when numeric."""
        header = response.headers.get("Retry-After")
        if header:
            try:
                return min(300.0, max(1.0, float(header)))
            except ValueError:
                pass
        return min(120.0, max(1.0, 2.0**attempt))

    def _extract_facet_values(self, payload: Dict[str, Any], facet: str) -> List[str]:
        """Extract facet values from different Shodan response formats."""
        values: List[str] = []
        facet_data = payload.get("facets", {}).get(facet)
        if isinstance(facet_data, list):
            for item in facet_data:
                if isinstance(item, dict):
                    value = item.get("value")
                    if value:
                        values.append(str(value))
                elif item:
                    values.append(str(item))
        elif isinstance(facet_data, dict):
            for key in facet_data.keys():
                if key:
                    values.append(str(key))
        return values

    def _extract_facet_values_from_html(self, html: str, facet: str) -> List[str]:
        """Parse facet values from Shodan facet HTML (layout changes over time)."""
        values: Set[str] = set()

        def _add(raw: str) -> None:
            text = html_module.unescape(raw).strip()
            if text:
                values.add(text)

        # Current layout (2024+): <div class="name"><a ...><strong>VALUE</strong></a>
        for match in re.finditer(
            r'<div class="name">\s*<a[^>]*>\s*<strong>([^<]+)</strong>',
            html,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            _add(match.group(1))

        # Alternate: class="text-dark"><strong>VALUE</strong>
        for match in re.finditer(
            r'class="text-dark"[^>]*>\s*<strong>([^<]+)</strong>',
            html,
            flags=re.IGNORECASE | re.DOTALL,
        ):
            _add(match.group(1))

        # Refinement links embed the value (reliable for ip facet)
        for match in re.finditer(r'ip%3A%22([^%"]+)%22', html):
            _add(unquote(match.group(1)))

        # Legacy markup
        for match in re.finditer(r'data-value="([^"]+)"', html):
            _add(match.group(1))

        if facet == "ip":
            values = {v for v in values if self._is_valid_ipv4(v)}

        return sorted(values)

    def _parse_facet_total_hosts(self, html: str) -> Optional[int]:
        """Parse 'Total: N' from facet HTML (total matching hosts for the query)."""
        m = re.search(r"Total:\s*([\d,]+)", html)
        if not m:
            return None
        raw = m.group(1).replace(",", "")
        try:
            return int(raw)
        except ValueError:
            return None

    def _search_facet_without_api_key(
        self,
        query: str,
        facet: str,
        max_results: Optional[int] = None,
        show_cap_notice: bool = True,
    ) -> List[str]:
        """Search Shodan facet endpoint without an API key.

        Shodan's facet HTML only includes a limited number of rows per facet (typically ~1000
        for the ip facet). The website search total (e.g. 10k+ hosts) counts all matches; the facet
        view is a *top-values* summary, not a full export. Full enumeration requires the API.
        """
        url = f"https://www.shodan.io/search/facet?query={quote_plus(query)}&facet={quote_plus(facet)}"
        max_attempts = 5
        body = ""
        last_error: Optional[Exception] = None
        try:
            for attempt in range(max_attempts):
                try:
                    response = self.session.get(url, timeout=30)
                except requests.exceptions.RequestException as e:
                    last_error = e
                    if attempt >= max_attempts - 1:
                        raise
                    time.sleep(min(30.0, 2.0**attempt))
                    continue

                if response.status_code in (400, 429):
                    # Match ipfinder behavior: treat 400/429 as retriable.
                    if attempt >= max_attempts - 1:
                        response.raise_for_status()
                    wait = min(30.0, max(2.0, 5.0 * (2.0**attempt)))
                    time.sleep(wait)
                    continue

                response.raise_for_status()
                body = response.text
                break

            if not body:
                if last_error:
                    raise last_error
                raise ShodanAPIError("Facet search returned empty response body.")

            total_hosts = self._parse_facet_total_hosts(body)

            values: List[str] = []
            content_type = response.headers.get("Content-Type", "").lower()
            if "application/json" in content_type:
                payload = response.json()
                values = self._extract_facet_values(payload, facet)
            else:
                # Try JSON first in case content-type is not set correctly.
                try:
                    payload = response.json()
                    values = self._extract_facet_values(payload, facet)
                except ValueError:
                    values = self._extract_facet_values_from_html(body, facet)

            if facet == "ip":
                values = [value for value in values if self._is_valid_ipv4(value)]

            if max_results is not None:
                values = values[:max_results]

            if (
                show_cap_notice
                and total_hosts is not None
                and len(values) < total_hosts
            ):
                self.console.print(
                    f"[yellow]Facet view: showing {len(values)} of ~{total_hosts:,} matching hosts "
                    f"(Shodan caps the facet list; not all results). "
                    f"Use API search with a key that allows /shodan/host/search to export the rest.[/yellow]"
                )
            return values
        except requests.exceptions.RequestException as e:
            raise ShodanAPIError(f"Facet search failed: {e}")
        except Exception as e:
            raise ShodanAPIError(f"Unexpected facet search error: {e}")

    def _search_ips_free_deep(
        self,
        query: str,
        max_results: Optional[int] = None,
        delay: float = 1.0,
        start_page: int = 1,
        end_page: Optional[int] = None,
    ) -> List[str]:
        """Collect IPs in free mode by pivoting facets (ipfinder-like city splitting)."""
        return list(
            self.iter_ips_free_deep(
                query=query,
                max_results=max_results,
                delay=delay,
                start_page=start_page,
                end_page=end_page,
            )
        )

    def iter_ips_free_deep(
        self,
        query: str,
        max_results: Optional[int] = None,
        delay: float = 1.0,
        start_page: int = 1,
        end_page: Optional[int] = None,
    ) -> Iterator[str]:
        """Yield unique IPs progressively in free-deep mode (no progress noise)."""
        # start_page/end_page are intentionally ignored in free-deep mode.
        ips_seen: Set[str] = set()
        yielded = 0

        base_ips = self._search_facet_without_api_key(
            query, "ip", show_cap_notice=False
        )
        for ip in base_ips:
            if ip in ips_seen:
                continue
            ips_seen.add(ip)
            yielded += 1
            yield ip
            if max_results and yielded >= max_results:
                return

        # If query is already small, no need to split.
        try:
            facet_url = (
                f"https://www.shodan.io/search/facet?query={quote_plus(query)}&facet=ip"
            )
            r = self.session.get(facet_url, timeout=30)
            total_hosts = (
                self._parse_facet_total_hosts(r.text) if r.status_code == 200 else None
            )
        except requests.exceptions.RequestException:
            total_hosts = None

        if total_hosts is not None and total_hosts < 1000:
            return

        cities = self._search_facet_without_api_key(
            query, "city", show_cap_notice=False
        )[:1000]
        for city in cities:
            subquery = f'{query} city:"{city}"'
            sub_ips = self._search_facet_without_api_key(
                subquery, "ip", show_cap_notice=False
            )
            for ip in sub_ips:
                if ip in ips_seen:
                    continue
                ips_seen.add(ip)
                yielded += 1
                yield ip
                if max_results and yielded >= max_results:
                    return
            if delay > 0:
                time.sleep(delay)

    def _group_matches_by_ip(
        self, results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Combine banners with the same ip_str: ports unioned, hostnames/domains/vulns merged."""
        grouped: Dict[str, Dict[str, Any]] = {}
        order: List[str] = []
        for match in results:
            ip = match.get("ip_str")
            if not ip:
                continue
            if ip not in grouped:
                grouped[ip] = dict(match)
                grouped[ip]["_all_ports"] = []
                grouped[ip]["hostnames"] = list(match.get("hostnames") or [])
                grouped[ip]["domains"] = list(match.get("domains") or [])
                grouped[ip]["_vulns_set"] = set()
                order.append(ip)
            entry = grouped[ip]
            port = match.get("port")
            if port is not None and port not in entry["_all_ports"]:
                entry["_all_ports"].append(port)
            for h in match.get("hostnames") or []:
                if h not in entry["hostnames"]:
                    entry["hostnames"].append(h)
            for d in match.get("domains") or []:
                if d not in entry["domains"]:
                    entry["domains"].append(d)
            vulns = match.get("vulns")
            if isinstance(vulns, dict):
                entry["_vulns_set"].update(vulns.keys())
            elif isinstance(vulns, list):
                entry["_vulns_set"].update(str(v) for v in vulns)
        out: List[Dict[str, Any]] = []
        for ip in order:
            entry = grouped[ip]
            entry["_all_ports"].sort()
            vulns_set = entry.pop("_vulns_set", set())
            if vulns_set:
                entry["vulns"] = sorted(vulns_set)
            out.append(entry)
        return out

    @staticmethod
    def _ports_from_host_payload(payload: Dict[str, Any]) -> List[int]:
        """Unique sorted ports from GET /shodan/host/{ip} JSON (`data` list)."""
        seen: Set[int] = set()
        out: List[int] = []
        for item in payload.get("data") or []:
            p = item.get("port")
            if isinstance(p, int) and p not in seen:
                seen.add(p)
                out.append(p)
        out.sort()
        return out

    def get_shodan_host(self, ip: str) -> Dict[str, Any]:
        """GET /shodan/host/{ip} — full host record (all banners / ports Shodan knows)."""
        api_key = self.config.get_api_key()
        if not api_key:
            raise ShodanAPIError("No API key configured.")
        params = {"key": api_key}
        return self._make_request(f"https://api.shodan.io/shodan/host/{ip}", params)

    def _apply_shodan_host_port_enrichment(self, rows: List[Dict[str, Any]]) -> None:
        """Set `_host_ports` from GET /shodan/host/{ip} (search-merged `_all_ports` is unchanged)."""
        failed: List[str] = []
        for row in rows:
            ip = row.get("ip_str")
            if not ip or not self._is_valid_ipv4(ip):
                continue
            try:
                payload = self.get_shodan_host(ip)
            except ShodanAPIError:
                failed.append(ip)
                continue
            ports = self._ports_from_host_payload(payload)
            if ports:
                row["_host_ports"] = ports
        if failed:
            self.console.print(
                f"[yellow]Host lookup failed for {len(failed)} IP(s); "
                "the `ports` column falls back to search matches for those rows.[/yellow]"
            )

    def prepare_detail_tabular_results(
        self,
        results: List[Dict[str, Any]],
        fields: Optional[List[str]],
    ) -> tuple[List[Dict[str, Any]], List[str]]:
        """Group by IP when port/ports columns are used; `ports` triggers full host lookups."""
        nf = self._normalize_fields(fields) or self.DEFAULT_TABLE_FIELDS
        want_port_cols = "port" in nf or "ports" in nf
        out = self._group_matches_by_ip(results) if want_port_cols else list(results)
        if "ports" in nf and out:
            self._apply_shodan_host_port_enrichment(out)
        return out, nf

    def _normalize_fields(self, fields: Optional[List[str]]) -> Optional[List[str]]:
        """Normalize user-provided field names for detail outputs."""
        if not fields:
            return None
        normalized: List[str] = []
        for field in fields:
            key = field.strip().lower()
            if not key:
                continue
            mapped = self.DETAIL_FIELD_ALIASES.get(key)
            if mapped is None:
                supported = sorted(set(self.DETAIL_FIELD_ALIASES.keys()))
                raise ShodanAPIError(
                    f"Unsupported field: {field}\n"
                    f"Supported: {', '.join(supported)}\n"
                    f"Run `sipg fields` for descriptions and examples."
                )
            if mapped not in normalized:
                normalized.append(mapped)
        if not normalized:
            raise ShodanAPIError("No valid fields provided.")
        return normalized

    def _get_detail_field_value(
        self,
        result: Dict[str, Any],
        field: str,
        domain_suffix_filter: Optional[List[str]] = None,
    ) -> str:
        """Extract displayable field value from a Shodan result."""
        location = result.get("location", {}) or {}
        if field == "ip_str":
            return str(result.get("ip_str", "N/A"))
        if field == "city":
            return str(location.get("city", "N/A"))
        if field == "country":
            return str(location.get("country_name", "N/A"))
        if field == "location":
            return (
                f"{location.get('city', 'N/A')}, {location.get('country_name', 'N/A')}"
            )
        if field == "hostnames":
            hostnames = result.get("hostnames", []) or []
            if domain_suffix_filter:
                hostnames = [
                    h
                    for h in hostnames
                    if self.name_matches_domain_suffix(str(h), domain_suffix_filter)
                ]
            return ", ".join(str(h) for h in hostnames) or "N/A"
        if field == "domains":
            domains = result.get("domains", []) or []
            if domain_suffix_filter:
                domains = [
                    d
                    for d in domains
                    if self.name_matches_domain_suffix(str(d), domain_suffix_filter)
                ]
            return ", ".join(str(d) for d in domains) or "N/A"
        if field == "port":
            # Search matches only (merged per IP in _group_matches_by_ip).
            merged = result.get("_all_ports")
            if merged:
                return ", ".join(str(p) for p in merged)
            port = result.get("port")
            return str(port) if port is not None else "N/A"
        if field == "ports":
            # Full host list when `ports` is in -F (from GET /shodan/host/{ip}); else search matches.
            host_ports = result.get("_host_ports")
            if host_ports:
                return ", ".join(str(p) for p in host_ports)
            merged = result.get("_all_ports")
            if merged:
                return ", ".join(str(p) for p in merged)
            port = result.get("port")
            return str(port) if port is not None else "N/A"
        if field == "vulns":
            vulns = result.get("vulns", {})
            if isinstance(vulns, dict):
                return ",".join(sorted(vulns.keys())) or "N/A"
            if isinstance(vulns, list):
                return ",".join([str(v) for v in vulns]) or "N/A"
            return "N/A"
        if field == "vuln_count":
            vulns = result.get("vulns", {})
            if isinstance(vulns, dict):
                return str(len(vulns))
            if isinstance(vulns, list):
                return str(len(vulns))
            return "0"

        value = result.get(field, "N/A")
        if isinstance(value, list):
            return ";".join(str(v) for v in value)
        return str(value)

    @staticmethod
    def _normalize_domain_suffixes(raw: Optional[str]) -> Optional[List[str]]:
        """Parse comma-separated suffixes; strip leading dots, lowercase (e.g. `.mil,.gov` → `mil,gov`)."""
        if not raw or not str(raw).strip():
            return None
        out: List[str] = []
        for part in str(raw).split(","):
            s = part.strip().lower().lstrip(".")
            if s:
                out.append(s)
        return out or None

    @staticmethod
    def name_matches_domain_suffix(name: str, suffixes: List[str]) -> bool:
        """True if hostname/domain ends at a label boundary with one of the suffixes.

        `army.mil` matches suffix `mil`; `mapshare.dsa.mil.ng` does not (ends with `.mil.ng`).
        """
        n = name.strip().lower()
        if not n:
            return False
        for suf in suffixes:
            if n == suf or n.endswith("." + suf):
                return True
        return False

    def _filter_asset_list(
        self, items: List[str], suffixes: Optional[List[str]]
    ) -> List[str]:
        if not suffixes:
            return items
        return [x for x in items if self.name_matches_domain_suffix(x, suffixes)]

    def search_assets(
        self,
        query: str,
        mode: str = "auto",
        collect: str = "ips",
        max_results: Optional[int] = None,
        delay: float = 1.0,
        start_page: int = 1,
        end_page: Optional[int] = None,
        domain_suffix: Optional[str] = None,
    ) -> Dict[str, List[str]]:
        """Search and collect assets (ips/domains/subdomains)."""
        collect_values = {part.strip().lower() for part in collect.split(",") if part.strip()}
        if not collect_values:
            collect_values = {"ips"}
        if "all" in collect_values:
            collect_values = {"ips", "domains", "subdomains"}
        collect_domains = "domains" in collect_values
        collect_subdomains = "subdomains" in collect_values
        collect_ips = "ips" in collect_values
        suffixes = self._normalize_domain_suffixes(domain_suffix)

        # Prefer API mode when available for richer and paginated data.
        api_key = self.config.get_api_key()
        use_api = mode == "api" or (mode == "auto" and api_key)
        if use_api:
            try:
                details = list(
                    self.search_with_details(
                        query=query,
                        max_results=max_results,
                        delay=delay,
                        start_page=start_page,
                        end_page=end_page,
                    )
                )
            except ShodanAPIError as e:
                # api-info can work while host/search returns 403 (plan / key scope). Auto mode
                # should still return facet data instead of failing outright.
                if mode != "auto":
                    raise
                if e.status_code not in (401, 403):
                    raise
                self.console.print(
                    f"[yellow]Shodan API search denied (HTTP {e.status_code}). "
                    "Falling back to free facet mode (top facet values only).[/yellow]"
                )
                use_api = False
            else:
                ips: List[str] = []
                domains: Set[str] = set()
                subdomains: Set[str] = set()
                for result in details:
                    ip = result.get("ip_str")
                    if ip and self._is_valid_ipv4(ip):
                        ips.append(ip)
                    if collect_domains:
                        for domain in result.get("domains", []) or []:
                            if domain:
                                d = str(domain)
                                if suffixes and not self.name_matches_domain_suffix(
                                    d, suffixes
                                ):
                                    continue
                                domains.add(d)
                    if collect_subdomains:
                        for hostname in result.get("hostnames", []) or []:
                            if hostname:
                                h = str(hostname)
                                if suffixes and not self.name_matches_domain_suffix(
                                    h, suffixes
                                ):
                                    continue
                                subdomains.add(h)
                return {
                    "ips": ips if collect_ips else [],
                    "domains": sorted(domains) if collect_domains else [],
                    "subdomains": sorted(subdomains) if collect_subdomains else [],
                }

        if mode == "api" and not api_key:
            raise ShodanAPIError(
                "No API key configured. Use 'sipg configure' or switch mode to 'free'."
            )

        if mode == "free":
            results: Dict[str, List[str]] = {"ips": [], "domains": [], "subdomains": []}
            if collect_ips:
                results["ips"] = self._search_ips_free_deep(
                    query=query,
                    max_results=max_results,
                    delay=delay,
                    start_page=start_page,
                    end_page=end_page,
                )
            # Domains/subdomains are still best-effort via facets in free mode.
            if collect_domains:
                results["domains"] = self._filter_asset_list(
                    self._search_facet_without_api_key(
                        query, "domain", max_results
                    ),
                    suffixes,
                )
            if collect_subdomains:
                results["subdomains"] = self._filter_asset_list(
                    self._search_facet_without_api_key(
                        query, "hostname", max_results
                    ),
                    suffixes,
                )
            return results

        # Free mode uses facets and returns top values only.
        results: Dict[str, List[str]] = {"ips": [], "domains": [], "subdomains": []}
        if collect_ips:
            results["ips"] = self._search_facet_without_api_key(
                query, "ip", max_results
            )
        if collect_domains:
            results["domains"] = self._filter_asset_list(
                self._search_facet_without_api_key(
                    query, "domain", max_results
                ),
                suffixes,
            )
        if collect_subdomains:
            results["subdomains"] = self._filter_asset_list(
                self._search_facet_without_api_key(
                    query, "hostname", max_results
                ),
                suffixes,
            )
        return results

    def _make_request(self, url: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make a request to the Shodan API (throttled; retries 429 / 503)."""
        is_shodan_api = "api.shodan.io" in url
        max_attempts = 8
        last_error: Optional[Exception] = None

        for attempt in range(max_attempts):
            if is_shodan_api:
                self._throttle_shodan_api()
            try:
                # api.shodan.io: use JSON Accept + python-requests User-Agent. The session
                # defaults to a browser UA for www.shodan.io facet HTML; Shodan has been
                # observed to return 403 on the REST API with that UA (bare requests.get
                # works with the same key).
                api_headers = None
                if is_shodan_api:
                    api_headers = {
                        "Accept": "application/json",
                        "User-Agent": f"python-requests/{requests.__version__}",
                    }
                response = self.session.get(
                    url, params=params, timeout=30, headers=api_headers
                )
            except requests.exceptions.RequestException as e:
                last_error = e
                if attempt >= max_attempts - 1:
                    msg = str(e).replace(self.config.get_api_key() or "", "<api_key>")
                    raise ShodanAPIError(f"API request failed: {msg}")
                self.console.print(
                    f"[yellow]Network error, retry {attempt + 1}/{max_attempts}...[/yellow]"
                )
                time.sleep(min(120.0, max(1.0, 2.0**attempt)))
                continue

            if response.status_code == 429:
                if attempt >= max_attempts - 1:
                    detail = (
                        "Shodan returned HTTP 429 Too Many Requests (rate limit). "
                        "Slow down: increase `--delay` and `--api-min-interval`, or set "
                        "environment variable SIPG_API_MIN_INTERVAL. See https://developer.shodan.io/api"
                    )
                    raise ShodanAPIError(detail, status_code=429)
                wait = self._retry_after_wait(response, attempt)
                self.console.print(
                    f"[yellow]Rate limited (HTTP 429). Waiting {wait:.1f}s "
                    f"(attempt {attempt + 1}/{max_attempts})...[/yellow]"
                )
                time.sleep(wait)
                continue

            if response.status_code == 503:
                if attempt >= max_attempts - 1:
                    raise ShodanAPIError(
                        "Shodan returned HTTP 503 Service Unavailable after retries.",
                        status_code=503,
                    )
                wait = self._retry_after_wait(response, attempt)
                self.console.print(
                    f"[yellow]Service unavailable (HTTP 503). Waiting {wait:.1f}s...[/yellow]"
                )
                time.sleep(wait)
                continue

            if response.status_code == 401:
                detail = (
                    "Shodan returned 401 Unauthorized. Verify your API key at "
                    "https://account.shodan.io/ or use `sipg search '<query>' --mode free`."
                )
                try:
                    body = response.json()
                    api_msg = (
                        body.get("error") or body.get("msg") or body.get("message")
                    )
                    if api_msg:
                        detail = f"{detail}\nAPI message: {api_msg}"
                except ValueError:
                    pass
                raise ShodanAPIError(detail, status_code=401)

            if response.status_code == 403:
                detail = (
                    "Shodan returned HTTP 403 Forbidden. This is usually not rate limiting "
                    "(Shodan typically uses HTTP 429 for throttling). Common causes: API key or "
                    "plan cannot use host search, credits, or IP/abuse policy. "
                    "See https://account.shodan.io/ and `sipg info`. "
                    "Use free mode: `sipg search '<query>' --mode free`; `sipg clear` removes the stored key."
                )
                try:
                    body = response.json()
                    api_msg = (
                        body.get("error") or body.get("msg") or body.get("message")
                    )
                    if api_msg:
                        detail = f"{detail}\nAPI message: {api_msg}"
                except ValueError:
                    pass
                raise ShodanAPIError(detail, status_code=403)

            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError as e:
                msg = str(e).replace(self.config.get_api_key() or "", "<api_key>")
                raise ShodanAPIError(
                    f"API request failed: {msg}",
                    status_code=response.status_code,
                )

            try:
                return response.json()
            except ValueError as e:
                raise ShodanAPIError(f"Invalid JSON response: {e}")
    
        if last_error:
            msg = str(last_error).replace(self.config.get_api_key() or "", "<api_key>")
            raise ShodanAPIError(f"API request failed: {msg}")
        raise ShodanAPIError("API request failed after retries.")

    def search_ips(
        self,
        query: str,
        max_results: Optional[int] = None,
        delay: float = 1.0,
        start_page: int = 1,
        end_page: Optional[int] = None,
    ) -> Iterator[str]:
        """Search for IP addresses using Shodan.
        
        Args:
            query: Search query string.
            max_results: Maximum number of results to return. If None, returns all.
            delay: Delay between API requests in seconds.
            start_page: The first page to fetch (1-based).
            end_page: The last page to fetch (inclusive). If None, fetches up to the last available page.
            
        Yields:
            IP addresses found.
            
        Raises:
            ShodanAPIError: If the API request fails.
        """
        api_key = self.config.get_api_key()
        if not api_key:
            raise ShodanAPIError(
                "No API key configured. Use 'sipg configure' to set your API key."
            )

        params = {"key": api_key, "query": query, "page": 1}
        
        try:
            initial_response = self._make_request(
                "https://api.shodan.io/shodan/host/search", params
            )
            total_results = initial_response.get("total", 0)
            
            if total_results == 0:
                self.console.print(
                    "[yellow]No results found for the given query.[/yellow]"
                )
                return
            
            self.console.print(f"[green]Found {total_results} total results[/green]")
            
            results_per_page = 100
            total_pages = (total_results + results_per_page - 1) // results_per_page
            
            if max_results:
                total_pages = min(
                    total_pages,
                    (max_results + results_per_page - 1) // results_per_page,
                )
            
            # Apply custom page range
            first_page = max(1, start_page)
            last_page = min(end_page if end_page else total_pages, total_pages)
            if first_page > last_page:
                return
            
            ip_count = 0
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            ) as progress:
                task = progress.add_task(
                    "Searching IPs...", total=last_page - first_page + 1
                )
                
                for page in range(first_page, last_page + 1):
                    progress.update(
                        task, description=f"Searching page {page}/{last_page}"
                    )
                    params["page"] = page
                    response = self._make_request(
                        "https://api.shodan.io/shodan/host/search", params
                    )
                    matches = response.get("matches", [])
                    for match in matches:
                        ip = match.get("ip_str")
                        if ip and self._is_valid_ipv4(ip):
                            ip_count += 1
                            yield ip
                            if max_results and ip_count >= max_results:
                                return
                    progress.advance(task)
                    if page < last_page:
                        time.sleep(delay)
        except ShodanAPIError:
            raise
        except Exception as e:
            raise ShodanAPIError(f"Unexpected error: {e}")
    
    def _is_valid_ipv4(self, ip: str) -> bool:
        """Check if an IP address is a valid IPv4 address.
        
        Args:
            ip: IP address string.
            
        Returns:
            True if valid IPv4, False otherwise.
        """
        try:
            return ipaddress.ip_address(ip).version == 4
        except ValueError:
            return False
    
    def search_with_details(
        self,
        query: str,
        max_results: Optional[int] = None,
        delay: float = 1.0,
        start_page: int = 1,
        end_page: Optional[int] = None,
    ) -> Iterator[Dict[str, Any]]:
        """Search for IP addresses with additional details.
        
        Args:
            query: Search query string.
            max_results: Maximum number of results to return.
            delay: Delay between API requests in seconds.
            start_page: The first page to fetch (1-based).
            end_page: The last page to fetch (inclusive). If None, fetches up to the last available page.
            
        Yields:
            Dictionary containing IP and additional details.
        """
        api_key = self.config.get_api_key()
        if not api_key:
            raise ShodanAPIError(
                "No API key configured. Use 'sipg configure' to set your API key."
            )

        params = {"key": api_key, "query": query, "page": 1}
        
        try:
            initial_response = self._make_request(
                "https://api.shodan.io/shodan/host/search", params
            )
            total_results = initial_response.get("total", 0)
            
            if total_results == 0:
                self.console.print(
                    "[yellow]No results found for the given query.[/yellow]"
                )
                return
            
            self.console.print(f"[green]Found {total_results} total results[/green]")
            
            results_per_page = 100
            total_pages = (total_results + results_per_page - 1) // results_per_page
            
            if max_results:
                total_pages = min(
                    total_pages,
                    (max_results + results_per_page - 1) // results_per_page,
                )
            
            # Apply custom page range
            first_page = max(1, start_page)
            last_page = min(end_page if end_page else total_pages, total_pages)
            if first_page > last_page:
                return
            
            result_count = 0
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console,
            ) as progress:
                task = progress.add_task(
                    "Searching details...", total=last_page - first_page + 1
                )
                
                for page in range(first_page, last_page + 1):
                    progress.update(
                        task, description=f"Searching page {page}/{last_page}"
                    )
                    params["page"] = page
                    response = self._make_request(
                        "https://api.shodan.io/shodan/host/search", params
                    )
                    matches = response.get("matches", [])
                    for match in matches:
                        ip = match.get("ip_str")
                        if ip and self._is_valid_ipv4(ip):
                            result_count += 1
                            yield match
                            if max_results and result_count >= max_results:
                                return
                    progress.advance(task)
                    if page < last_page:
                        time.sleep(delay)
        except ShodanAPIError:
            raise
        except Exception as e:
            raise ShodanAPIError(f"Unexpected error: {e}")
    
    def print_detail_table_rows(
        self,
        prepared: List[Dict[str, Any]],
        normalized_fields: List[str],
        domain_suffix_filter: Optional[List[str]] = None,
    ) -> None:
        """Render a Rich table from rows returned by prepare_detail_tabular_results."""
        if not prepared:
            self.console.print("[yellow]No results to display.[/yellow]")
            return
        header_map = {
            "ip_str": "IP",
            "port": "Port",
            "ports": "Ports",
            "transport": "Transport",
            "org": "Organization",
            "asn": "ASN",
            "isp": "ISP",
            "city": "City",
            "country": "Country",
            "location": "Location",
            "hostnames": "Hostnames",
            "domains": "Domains",
            "product": "Product",
            "os": "OS",
            "timestamp": "Timestamp",
            "vulns": "Vulns",
            "vuln_count": "Vuln Count",
        }
        table = Table(title="Shodan Search Results", show_lines=True)
        for field in normalized_fields:
            table.add_column(header_map.get(field, field.upper()))

        for result in prepared:
            row = [
                self._get_detail_field_value(
                    result, field, domain_suffix_filter
                )
                for field in normalized_fields
            ]
            table.add_row(*row)

        self.console.print(table)

    def display_results_table(
        self,
        results: List[Dict[str, Any]],
        fields: Optional[List[str]] = None,
        domain_suffix_filter: Optional[List[str]] = None,
    ) -> None:
        """Display results in a formatted table (groups by IP when port/ports columns are used)."""
        if not results:
            self.console.print("[yellow]No results to display.[/yellow]")
            return
        prepared, nf = self.prepare_detail_tabular_results(results, fields)
        self.print_detail_table_rows(prepared, nf, domain_suffix_filter)
    
    def save_results_to_file(
        self, results: List[str], filename: str, add_protocol: bool = False
    ) -> None:
        """Save results to a file.
        
        Args:
            results: List of IP addresses.
            filename: Output filename.
        """
        try:
            with open(filename, "w", encoding="utf-8") as f:
                for value in results:
                    if add_protocol and self._is_valid_ipv4(value):
                        f.write(f"https://{value}\n")
                    else:
                        f.write(f"{value}\n")
            self.console.print(f"[green]Results saved to {filename}[/green]")
        except IOError as e:
            self.console.print(f"[red]Failed to save results: {e}[/red]")

    def save_assets_to_file(
        self,
        assets: Dict[str, List[str]],
        filename: str,
        output_format: str = "txt",
        fields: Optional[List[str]] = None,
    ) -> None:
        """Save collected assets in txt/json/csv formats."""
        try:
            if output_format == "json":
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(assets, f, indent=2, ensure_ascii=False)
            elif output_format == "csv":
                with open(filename, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    selected_fields = fields or ["type", "value"]
                    valid_fields = {"type", "value"}
                    if any(field not in valid_fields for field in selected_fields):
                        raise ShodanAPIError(
                            "Collect CSV fields only support: type,value"
                        )
                    writer.writerow(selected_fields)
                    for asset_type in ("ips", "domains", "subdomains"):
                        for value in assets.get(asset_type, []):
                            row_data = {"type": asset_type, "value": value}
                            writer.writerow(
                                [row_data.get(field, "") for field in selected_fields]
                            )
            else:
                with open(filename, "w", encoding="utf-8") as f:
                    for asset_type in ("ips", "domains", "subdomains"):
                        for value in assets.get(asset_type, []):
                            f.write(f"{value}\n")
            self.console.print(f"[green]Results saved to {filename}[/green]")
        except IOError as e:
            self.console.print(f"[red]Failed to save results: {e}[/red]")
    
    def save_detailed_results_to_file(
        self,
        results: List[Dict[str, Any]],
        filename: str,
        output_format: str = "json",
        fields: Optional[List[str]] = None,
        csv_rows: Optional[List[Dict[str, Any]]] = None,
        csv_columns: Optional[List[str]] = None,
        domain_suffix_filter: Optional[List[str]] = None,
    ) -> None:
        """Save detailed API results in json/csv/txt formats.

        Pass csv_rows/csv_columns from prepare_detail_tabular_results so CSV matches the table.
        """
        try:
            if output_format == "json":
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
            elif output_format == "csv":
                if csv_rows is not None and csv_columns is not None:
                    selected_fields = csv_columns
                    export_results = csv_rows
                else:
                    selected_fields = (
                        self._normalize_fields(fields) or self.DEFAULT_DETAIL_CSV_FIELDS
                    )
                    export_results = (
                        self._group_matches_by_ip(results)
                        if "port" in selected_fields or "ports" in selected_fields
                        else results
                    )
                with open(filename, "w", encoding="utf-8", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow(selected_fields)
                    for result in export_results:
                        writer.writerow(
                            [
                                self._get_detail_field_value(
                                    result, field, domain_suffix_filter
                                )
                                for field in selected_fields
                            ]
                        )
            else:
                with open(filename, "w", encoding="utf-8") as f:
                    for result in results:
                        f.write(json.dumps(result, ensure_ascii=False))
                        f.write("\n")
            self.console.print(f"[green]Detailed results saved to {filename}[/green]")
        except IOError as e:
            self.console.print(f"[red]Failed to save detailed results: {e}[/red]")

    def probe_host_search_access(self) -> Dict[str, Any]:
        """Minimal GET /shodan/host/search to verify Search API access (uses 1 query credit)."""
        api_key = self.config.get_api_key()
        if not api_key:
            raise ShodanAPIError("No API key configured.")
        params = {"key": api_key, "query": "apache", "page": 1}
        return self._make_request(
            "https://api.shodan.io/shodan/host/search", params
        )
    
    def get_api_info(self) -> Dict[str, Any]:
        """Get information about the current API key.
        
        Returns:
            Dictionary containing API information.
            
        Raises:
            ShodanAPIError: If the API request fails.
        """
        api_key = self.config.get_api_key()
        if not api_key:
            raise ShodanAPIError("No API key configured.")
        
        params = {"key": api_key}
        return self._make_request("https://api.shodan.io/api-info", params)
