#!/usr/bin/env python3
"""
===============================================================================
Threat Intelligence (TI) Enrichment Engine
ARZENS Internship Program - AI, Automation & Security Track (Week 06-07)
Task 2 Deliverable: ti_enricher.py

Author: Threat Intel Systems Engineer
Description:
    Production-grade CLI tool that ingests single or batch Indicators of
    Compromise (IOCs), automates queries against VirusTotal (v3), AbuseIPDB (v2),
    and AlienVault OTX (v1), enforces strict API rate limits, implements a
    24h query cache, calculates a normalized composite risk score (0-100),
    and produces styled terminal tables, JSON, and CSV outputs.

Risk Scoring Algorithm:
    Refer to `compute_risk_score()` for the comprehensive mathematical formulation.
===============================================================================
"""

import argparse
import base64
import csv
import ipaddress
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Force UTF-8 encoding on standard streams to support all platforms smoothly
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Initialize Rich Console with ASCII-safe box and legacy windows mode disabled
console = Console(safe_box=True, legacy_windows=False)




# =============================================================================
# 1. Indicator Type Detection & Validation
# =============================================================================

class IndicatorType:
    IPV4 = "ipv4"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    UNKNOWN = "unknown"


def detect_indicator_type(indicator: str) -> str:
    """
    Deterministically identifies the indicator type using strict RFC/standard regexes.
    Supported types: IPv4, Domain, Hash (MD5, SHA1, SHA256), and URL.
    """
    clean_val = indicator.strip()

    # 1. Check IPv4
    try:
        ip = ipaddress.ip_address(clean_val)
        if isinstance(ip, ipaddress.IPv4Address):
            return IndicatorType.IPV4
    except ValueError:
        pass

    # 2. Check Hashes (MD5: 32, SHA1: 40, SHA256: 64 hex characters)
    if re.fullmatch(r"[a-fA-F0-9]{32}", clean_val):
        return IndicatorType.HASH  # MD5
    if re.fullmatch(r"[a-fA-F0-9]{40}", clean_val):
        return IndicatorType.HASH  # SHA1
    if re.fullmatch(r"[a-fA-F0-9]{64}", clean_val):
        return IndicatorType.HASH  # SHA256

    # 3. Check URL (must have scheme or path)
    if re.match(r"^https?://", clean_val, re.IGNORECASE) or ("/" in clean_val and "." in clean_val.split("/")[0]):
        return IndicatorType.URL

    # 4. Check Domain (FQDN format)
    domain_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if re.fullmatch(domain_regex, clean_val):
        return IndicatorType.DOMAIN

    return IndicatorType.UNKNOWN


# =============================================================================
# 2. Configuration & Cache Management
# =============================================================================

DEFAULT_CONFIG_PATH = "config.yaml"
DEFAULT_CACHE_PATH = "cache.json"


def load_config(config_path: str = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """
    Loads YAML configuration and resolves API keys with environment variable fallbacks.
    """
    cfg: Dict[str, Any] = {}
    path = Path(config_path)

    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}

    api_keys = cfg.get("api_keys", {})
    # Fallback to environment variables
    vt_key = os.environ.get("VT_API_KEY", api_keys.get("virustotal", ""))
    abuse_key = os.environ.get("ABUSEIPDB_API_KEY", api_keys.get("abuseipdb", ""))
    otx_key = os.environ.get("OTX_API_KEY", api_keys.get("alienvault_otx", ""))

    cfg["api_keys"] = {
        "virustotal": vt_key.strip(),
        "abuseipdb": abuse_key.strip(),
        "alienvault_otx": otx_key.strip(),
    }

    # Default rate limits and cache
    if "rate_limits" not in cfg:
        cfg["rate_limits"] = {
            "virustotal_min_interval_seconds": 15.0,
            "request_timeout_seconds": 25,
            "max_retries": 3,
            "retry_backoff_factor": 2.0,
        }

    if "cache" not in cfg:
        cfg["cache"] = {
            "enabled": True,
            "filepath": DEFAULT_CACHE_PATH,
            "ttl_hours": 24,
        }

    return cfg


class CacheManager:
    """
    JSON-backed local cache with per-indicator TTL validation.
    Prevents duplicate API calls, conserving rate limits and API quota.
    """

    def __init__(self, filepath: str = DEFAULT_CACHE_PATH, ttl_hours: float = 24.0, enabled: bool = True):
        self.filepath = Path(filepath)
        self.ttl_seconds = ttl_hours * 3600.0
        self.enabled = enabled
        self._cache: Dict[str, Any] = {}
        self._load()

    def _load(self):
        if not self.enabled:
            return
        if self.filepath.exists():
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
            except Exception as e:
                console.print(f"[yellow]Warning: Could not read cache file ({e}). Starting fresh.[/yellow]")
                self._cache = {}
        else:
            self._cache = {}

    def get(self, indicator: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        entry = self._cache.get(indicator)
        if not entry:
            return None

        # Check TTL
        cached_time_str = entry.get("cached_at")
        if not cached_time_str:
            return None

        try:
            cached_dt = datetime.fromisoformat(cached_time_str)
            now = datetime.now(timezone.utc)
            if (now - cached_dt).total_seconds() > self.ttl_seconds:
                # Expired cache entry
                return None
            return entry.get("data")
        except Exception:
            return None

    def set(self, indicator: str, data: Dict[str, Any]):
        if not self.enabled:
            return
        self._cache[indicator] = {
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }

    def save(self):
        if not self.enabled:
            return
        try:
            # Ensure parent directory exists
            self.filepath.parent.mkdir(parents=True, exist_ok=True)
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2)
        except Exception as e:
            console.print(f"[red]Error writing cache file: {e}[/red]")


# =============================================================================
# 3. Rate Limit Management & Safe API Calling
# =============================================================================

class RateLimiter:
    """
    Enforces minimum intervals between consecutive API calls.
    Specifically guarantees compliance with VirusTotal free tier (4 req/min = 15s interval).
    """

    def __init__(self, min_interval_seconds: float = 15.0):
        self.min_interval = min_interval_seconds
        self.last_call_time: float = 0.0

    def wait(self, service_name: str = "VirusTotal"):
        now = time.time()
        elapsed = now - self.last_call_time
        if elapsed < self.min_interval:
            sleep_time = self.min_interval - elapsed
            console.print(
                f"[dim cyan]  [*] RateLimiter: Pacing {service_name} (waiting {sleep_time:.1f}s to respect free-tier quota)...[/dim cyan]"
            )
            time.sleep(sleep_time)
        self.last_call_time = time.time()


# =============================================================================
# 4. Threat Intelligence Source Clients
# =============================================================================

class ThreatIntelEngine:
    """
    Coordinates multi-feed ingestion across VirusTotal, AbuseIPDB, and AlienVault OTX.
    Handles rate-limiting, error fallbacks, and result normalization.
    """

    def __init__(self, config: Dict[str, Any], cache_manager: Optional[CacheManager] = None):
        self.config = config
        self.cache = cache_manager
        self.api_keys = config.get("api_keys", {})
        self.timeout = config.get("rate_limits", {}).get("request_timeout_seconds", 25)
        self.max_retries = config.get("rate_limits", {}).get("max_retries", 3)
        self.backoff_factor = config.get("rate_limits", {}).get("retry_backoff_factor", 2.0)

        # Initialize rate limiter for VirusTotal
        vt_interval = config.get("rate_limits", {}).get("virustotal_min_interval_seconds", 15.0)
        self.vt_limiter = RateLimiter(min_interval_seconds=vt_interval)

        # HTTP Session with reusable connection pooling
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Arzens-TI-Enricher/1.0"})

    def _execute_request(
        self,
        url: str,
        headers: Dict[str, str],
        params: Optional[Dict[str, Any]] = None,
        service: str = "API",
    ) -> Tuple[int, Optional[Dict[str, Any]], str]:
        """
        Executes an HTTP request with exponential backoff on HTTP 429 and transient errors.
        """
        for attempt in range(1, self.max_retries + 1):
            try:
                response = self.session.get(url, headers=headers, params=params, timeout=self.timeout)
                if response.status_code == 200:
                    return 200, response.json(), "OK"
                elif response.status_code == 404:
                    return 404, None, "Not found in dataset"
                elif response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 15))
                    console.print(
                        f"[yellow]  [!] {service} Rate Limited (HTTP 429). Attempt {attempt}/{self.max_retries}. Backing off {retry_after}s...[/yellow]"
                    )
                    time.sleep(retry_after)
                    continue
                elif response.status_code in [401, 403]:
                    return response.status_code, None, f"Authentication failure: Invalid or unauthorized API key"
                else:
                    return response.status_code, None, f"HTTP Error {response.status_code}: {response.text[:120]}"
            except requests.exceptions.Timeout:
                if attempt == self.max_retries:
                    return 408, None, f"Connection timed out after {self.timeout}s"
                time.sleep(self.backoff_factor * attempt)
            except requests.exceptions.RequestException as e:
                return 500, None, f"Network exception: {str(e)}"

        return 429, None, "Rate limit retries exhausted"

    # -------------------------------------------------------------------------
    # Feed 1: VirusTotal (v3)
    # -------------------------------------------------------------------------
    def query_virustotal(self, indicator: str, ind_type: str) -> Dict[str, Any]:
        """
        Queries VirusTotal v3 REST API.
        Endpoints:
            - IP:      /api/v3/ip_addresses/{ip}
            - Domain:  /api/v3/domains/{domain}
            - Hash:    /api/v3/files/{hash}
            - URL:     /api/v3/urls/{url_id}
        """
        vt_key = self.api_keys.get("virustotal")
        if not vt_key:
            return {"status": "error", "error": "VirusTotal API key missing"}

        base_url = "https://www.virustotal.com/api/v3"
        endpoint = ""

        if ind_type == IndicatorType.IPV4:
            endpoint = f"{base_url}/ip_addresses/{indicator}"
        elif ind_type == IndicatorType.DOMAIN:
            endpoint = f"{base_url}/domains/{indicator}"
        elif ind_type == IndicatorType.HASH:
            endpoint = f"{base_url}/files/{indicator}"
        elif ind_type == IndicatorType.URL:
            # URL ID is base64url encoded string without padding '='
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
            endpoint = f"{base_url}/urls/{url_id}"
        else:
            return {"status": "unsupported", "error": f"Unsupported indicator type: {ind_type}"}

        # Apply rate limiting before outbound call
        self.vt_limiter.wait(service_name="VirusTotal v3")

        console.print(f"[dim]    -> Querying VirusTotal v3 ({ind_type})...[/dim]")
        headers = {"x-apikey": vt_key, "Accept": "application/json"}
        status_code, data, msg = self._execute_request(endpoint, headers=headers, service="VirusTotal")

        if status_code == 200 and data:
            attr = data.get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            reputation = attr.get("reputation", 0)
            threat_tags = attr.get("tags", [])
            as_owner = attr.get("as_owner", attr.get("network", "N/A"))

            return {
                "status": "success",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total_engines": sum(stats.values()) if stats else 0,
                "reputation": reputation,
                "tags": threat_tags[:5],
                "owner": as_owner,
            }
        elif status_code == 404:
            return {
                "status": "not_found",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total_engines": 0,
                "reputation": 0,
                "tags": [],
                "message": "Indicator not cataloged in VirusTotal",
            }
        else:
            return {"status": "error", "error": msg, "http_code": status_code}

    # -------------------------------------------------------------------------
    # Feed 2: AbuseIPDB (v2)
    # -------------------------------------------------------------------------
    def query_abuseipdb(self, indicator: str, ind_type: str) -> Dict[str, Any]:
        """
        Queries AbuseIPDB v2 REST API (Check endpoint).
        Strictly applies to IPv4 addresses only.
        """
        if ind_type != IndicatorType.IPV4:
            return {
                "status": "n_a",
                "reason": "AbuseIPDB only supports IP indicators",
                "score": 0,
                "total_reports": 0,
                "is_whitelisted": False,
            }

        abuse_key = self.api_keys.get("abuseipdb")
        if not abuse_key:
            return {"status": "error", "error": "AbuseIPDB API key missing"}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": abuse_key, "Accept": "application/json"}
        params = {"ipAddress": indicator, "maxAgeInDays": 90, "verbose": True}

        console.print(f"[dim]    -> Querying AbuseIPDB v2 (IPv4)...[/dim]")
        status_code, data, msg = self._execute_request(url, headers=headers, params=params, service="AbuseIPDB")

        if status_code == 200 and data:
            res = data.get("data", {})
            return {
                "status": "success",
                "score": res.get("abuseConfidenceScore", 0),
                "total_reports": res.get("totalReports", 0),
                "is_whitelisted": res.get("isWhitelisted", False),
                "country": res.get("countryCode", "N/A"),
                "isp": res.get("isp", "N/A"),
                "usage_type": res.get("usageType", "N/A"),
                "domain": res.get("domain", "N/A"),
                "last_reported_at": res.get("lastReportedAt"),
            }
        else:
            return {"status": "error", "error": msg, "http_code": status_code}

    # -------------------------------------------------------------------------
    # Feed 3: AlienVault OTX (v1)
    # -------------------------------------------------------------------------
    def query_alienvault_otx(self, indicator: str, ind_type: str) -> Dict[str, Any]:
        """
        Queries AlienVault OTX REST API general indicator endpoint.
        Endpoints:
            - IPv4:   /api/v1/indicators/IPv4/{ip}/general
            - Domain: /api/v1/indicators/domain/{domain}/general
            - Hash:   /api/v1/indicators/file/{hash}/general
            - URL:    /api/v1/indicators/url/{url}/general
        """
        otx_key = self.api_keys.get("alienvault_otx")
        if not otx_key:
            return {"status": "error", "error": "AlienVault OTX API key missing"}

        base_url = "https://otx.alienvault.com/api/v1/indicators"
        endpoint = ""

        if ind_type == IndicatorType.IPV4:
            endpoint = f"{base_url}/IPv4/{indicator}/general"
        elif ind_type == IndicatorType.DOMAIN:
            endpoint = f"{base_url}/domain/{indicator}/general"
        elif ind_type == IndicatorType.HASH:
            endpoint = f"{base_url}/file/{indicator}/general"
        elif ind_type == IndicatorType.URL:
            # For URL, general endpoint accepts the URL string
            endpoint = f"{base_url}/url/{indicator}/general"
        else:
            return {"status": "unsupported", "error": f"Unsupported indicator type: {ind_type}"}

        headers = {"X-OTX-API-KEY": otx_key, "Accept": "application/json"}
        params = {"limit": 10}
        console.print(f"[dim]    -> Querying AlienVault OTX ({ind_type})...[/dim]")
        status_code, data, msg = self._execute_request(endpoint, headers=headers, params=params, service="AlienVault OTX")

        if status_code == 200 and data:
            pulse_info = data.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)
            pulses = pulse_info.get("pulses", [])

            # Aggregate tags and adversary metadata
            tags = set()
            adversaries = set()
            malware_families = set()
            for p in pulses[:15]:
                for t in p.get("tags", []):
                    tags.add(t.lower())
                adv = p.get("adversary")
                if adv:
                    adversaries.add(adv)
                mal = p.get("malware_families", [])
                if isinstance(mal, list):
                    for m in mal:
                        malware_families.add(m if isinstance(m, str) else str(m))

            return {
                "status": "success",
                "pulse_count": pulse_count,
                "pulses_analyzed": len(pulses),
                "tags": sorted(list(tags))[:10],
                "adversaries": sorted(list(adversaries))[:5],
                "malware_families": sorted(list(malware_families))[:5],
            }
        elif status_code == 404:
            return {
                "status": "not_found",
                "pulse_count": 0,
                "pulses_analyzed": 0,
                "tags": [],
                "adversaries": [],
                "malware_families": [],
                "message": "Indicator not cataloged in AlienVault OTX",
            }
        else:
            return {"status": "error", "error": msg, "http_code": status_code}

    # -------------------------------------------------------------------------
    # Composite Enrichment Dispatcher
    # -------------------------------------------------------------------------
    def enrich_indicator(self, indicator: str, force_live: bool = False) -> Dict[str, Any]:
        """
        Orchestrates cache lookup, parallel/sequential feed queries, risk scoring,
        and response formatting for a single indicator.
        """
        clean_ind = indicator.strip()
        ind_type = detect_indicator_type(clean_ind)

        # 1. Check local Cache
        if not force_live and self.cache:
            cached_result = self.cache.get(clean_ind)
            if cached_result:
                cached_result["from_cache"] = True
                return cached_result

        console.print(f"[bold cyan][*] Enriching [{ind_type.upper()}] {clean_ind}...[/bold cyan]")

        # 2. Query Feeds
        vt_res = self.query_virustotal(clean_ind, ind_type)
        abuse_res = self.query_abuseipdb(clean_ind, ind_type)
        otx_res = self.query_alienvault_otx(clean_ind, ind_type)

        # 3. Compute Risk Score & Tier
        risk_score, risk_tier, score_breakdown = compute_risk_score(
            ind_type=ind_type,
            vt_data=vt_res,
            abuse_data=abuse_res,
            otx_data=otx_res,
            weights_cfg=self.config.get("scoring", {}).get("weights", {}),
        )

        # 4. Synthesize consolidated tags
        consolidated_tags = set()
        if vt_res.get("status") == "success":
            consolidated_tags.update(vt_res.get("tags", []))
        if otx_res.get("status") == "success":
            consolidated_tags.update(otx_res.get("tags", []))
            consolidated_tags.update(otx_res.get("malware_families", []))

        result: Dict[str, Any] = {
            "indicator": clean_ind,
            "type": ind_type,
            "risk_score": risk_score,
            "risk_tier": risk_tier,
            "score_breakdown": score_breakdown,
            "tags": sorted(list(consolidated_tags))[:10],
            "enriched_at": datetime.now(timezone.utc).isoformat(),
            "from_cache": False,
            "sources": {
                "virustotal": vt_res,
                "abuseipdb": abuse_res,
                "alienvault_otx": otx_res,
            },
        }

        # 5. Persist to cache
        if self.cache:
            self.cache.set(clean_ind, result)
            self.cache.save()

        return result


# =============================================================================
# 5. Mathematical Risk Scoring Algorithm
# =============================================================================

def compute_risk_score(
    ind_type: str,
    vt_data: Dict[str, Any],
    abuse_data: Dict[str, Any],
    otx_data: Dict[str, Any],
    weights_cfg: Optional[Dict[str, Any]] = None,
) -> Tuple[int, str, Dict[str, Any]]:
    """
    ===========================================================================
    MATHEMATICAL RISK SCORING ALGORITHM (0 - 100)
    ===========================================================================
    Formula & Methodology:
    ----------------------
    The composite risk score is calculated using multi-source Bayesian evidence
    fusion with domain-specific feed weighting and sanity caps.

    1. Sub-Score Derivation (0 to 100 each):
       - VirusTotal Component (S_vt):
         Evaluates malicious engine detections (M) and suspicious detections (S).
         S_vt = min(100.0, (M * 14.0) + (S * 4.0))
         * Rationale: Standard AV engines have high confidence; >= 6 engines detecting
           a malicious payload guarantees an AV score of 100/100.

       - AbuseIPDB Component (S_abuse):
         Natively reported as abuseConfidenceScore (0-100).
         If indicator is clean whitelisted (e.g. Google/Cloudflare DNS) and VT M=0,
         S_abuse is explicitly dampened to 0.0.

       - AlienVault OTX Component (S_otx):
         Evaluates community threat pulse presence (P) and critical threat tags (T):
         Critical tags include: 'ransomware', 'c2', 'malware', 'botnet', 'exploit', 'phishing'.
         S_otx = min(100.0, (P * 12.0) + (len(T_critical) * 6.0))

    2. Indicator-Specific Weighting Fusion:
       - For IPv4:
         All three sources are applicable.
         Weights: w_vt = 0.35, w_abuse = 0.45, w_otx = 0.20
         Composite Risk = (0.35 * S_vt) + (0.45 * S_abuse) + (0.20 * S_otx)

       - For Non-IPs (Domain, Hash, URL):
         AbuseIPDB is not applicable (N/A).
         Weights: w_vt = 0.70, w_otx = 0.30
         Composite Risk = (0.70 * S_vt) + (0.30 * S_otx)

    3. Risk Tiers:
       - 00 - 19: Clean / Low Risk
       - 20 - 49: Suspicious / Medium Risk
       - 50 - 74: High Risk
       - 75 - 100: Critical / Malicious
    ===========================================================================
    """
    if weights_cfg is None:
        weights_cfg = {}

    # 1. VirusTotal Sub-Score (S_vt)
    s_vt = 0.0
    if vt_data.get("status") == "success":
        m = vt_data.get("malicious", 0)
        s = vt_data.get("suspicious", 0)
        s_vt = min(100.0, (m * 14.0) + (s * 4.0))

    # 2. AbuseIPDB Sub-Score (S_abuse)
    s_abuse = 0.0
    is_whitelisted = False
    if abuse_data.get("status") == "success":
        s_abuse = float(abuse_data.get("score", 0))
        is_whitelisted = abuse_data.get("is_whitelisted", False)
        if is_whitelisted and vt_data.get("malicious", 0) == 0:
            s_abuse = 0.0

    # 3. AlienVault OTX Sub-Score (S_otx)
    s_otx = 0.0
    if otx_data.get("status") == "success":
        pulse_count = otx_data.get("pulse_count", 0)
        tags = [t.lower() for t in otx_data.get("tags", [])]
        crit_keywords = ["malware", "ransomware", "c2", "botnet", "exploit", "trojan", "phishing"]
        crit_tags = [t for t in tags if any(k in t for k in crit_keywords)]
        s_otx = min(100.0, (pulse_count * 12.0) + (len(crit_tags) * 6.0))

    # 4. Indicator-Weighted Composite Score
    if ind_type == IndicatorType.IPV4:
        w = weights_cfg.get("ip", {"virustotal": 0.35, "abuseipdb": 0.45, "alienvault_otx": 0.20})
        w_vt = w.get("virustotal", 0.35)
        w_ab = w.get("abuseipdb", 0.45)
        w_otx = w.get("alienvault_otx", 0.20)
        composite = (w_vt * s_vt) + (w_ab * s_abuse) + (w_otx * s_otx)
    else:
        # Non-IP indicator: AbuseIPDB is N/A
        w_key = "domain" if ind_type == IndicatorType.DOMAIN else ("hash" if ind_type == IndicatorType.HASH else "url")
        w = weights_cfg.get(w_key, {"virustotal": 0.70, "alienvault_otx": 0.30})
        w_vt = w.get("virustotal", 0.70)
        w_otx = w.get("alienvault_otx", 0.30)
        composite = (w_vt * s_vt) + (w_otx * s_otx)

    # Whitelist clamp: If confirmed whitelisted and clean across engines, force 0
    if is_whitelisted and vt_data.get("malicious", 0) == 0 and otx_data.get("pulse_count", 0) == 0:
        composite = 0.0

    final_score = int(round(min(100.0, max(0.0, composite))))

    # Determine Tier
    if final_score >= 75:
        tier = "CRITICAL"
    elif final_score >= 50:
        tier = "HIGH"
    elif final_score >= 20:
        tier = "SUSPICIOUS"
    else:
        tier = "CLEAN"

    breakdown = {
        "virustotal_subscore": round(s_vt, 1),
        "abuseipdb_subscore": round(s_abuse, 1),
        "alienvault_otx_subscore": round(s_otx, 1),
        "weights_applied": {
            "virustotal": w_vt,
            "abuseipdb": w_ab if ind_type == IndicatorType.IPV4 else 0.0,
            "alienvault_otx": w_otx,
        },
    }

    return final_score, tier, breakdown


# =============================================================================
# 6. Formatting & Output Renderers
# =============================================================================

def get_tier_style(tier: str) -> str:
    """Returns color styling for risk tiers."""
    mapping = {
        "CRITICAL": "bold red",
        "HIGH": "bold color(208)",  # Orange
        "SUSPICIOUS": "bold yellow",
        "CLEAN": "bold green",
    }
    return mapping.get(tier, "white")


def render_terminal_table(results: List[Dict[str, Any]]):
    """
    Renders an executive-grade styled table using Rich.
    """
    table = Table(
        title="[ARZENS TI ENGINE] Threat Intelligence Enrichment Summary",
        show_header=True,
        header_style="bold magenta",
        show_lines=True,
    )

    table.add_column("Indicator", style="cyan", no_wrap=False, max_width=32)
    table.add_column("Type", style="dim", justify="center")
    table.add_column("Risk Score", justify="center")
    table.add_column("Tier", justify="center")
    table.add_column("VirusTotal", justify="center")
    table.add_column("AbuseIPDB", justify="center")
    table.add_column("OTX Pulses", justify="center")
    table.add_column("Tags & Threat Context", style="dim")

    for r in results:
        ind = r.get("indicator", "")
        ind_type = r.get("type", "").upper()
        score = r.get("risk_score", 0)
        tier = r.get("risk_tier", "CLEAN")
        tier_style = get_tier_style(tier)

        # VT Column
        vt = r.get("sources", {}).get("virustotal", {})
        if vt.get("status") == "success":
            m = vt.get("malicious", 0)
            tot = vt.get("total_engines", 0)
            vt_text = f"[red]{m}[/red]/{tot}" if m > 0 else f"[green]0[/green]/{tot}"
        elif vt.get("status") == "not_found":
            vt_text = "[dim]Not Found[/dim]"
        else:
            vt_text = f"[yellow]{vt.get('status', 'Error')}[/yellow]"

        # AbuseIPDB Column
        abuse = r.get("sources", {}).get("abuseipdb", {})
        if abuse.get("status") == "success":
            ab_score = abuse.get("score", 0)
            reps = abuse.get("total_reports", 0)
            ab_style = "red" if ab_score > 50 else ("yellow" if ab_score > 20 else "green")
            vt_abuse_text = f"[{ab_style}]{ab_score}%[/] ({reps} reps)"
        elif abuse.get("status") == "n_a":
            vt_abuse_text = "[dim]N/A (Non-IP)[/dim]"
        else:
            vt_abuse_text = f"[yellow]{abuse.get('status', 'Error')}[/yellow]"

        # OTX Column
        otx = r.get("sources", {}).get("alienvault_otx", {})
        if otx.get("status") == "success":
            p_cnt = otx.get("pulse_count", 0)
            otx_style = "red" if p_cnt >= 5 else ("yellow" if p_cnt > 0 else "green")
            otx_text = f"[{otx_style}]{p_cnt} pulses[/]"
        elif otx.get("status") == "not_found":
            otx_text = "[dim]0 pulses[/dim]"
        else:
            otx_text = f"[yellow]{otx.get('status', 'Error')}[/yellow]"

        # Tags
        tags = r.get("tags", [])
        tags_str = ", ".join(tags[:4]) if tags else "-"

        table.add_row(
            ind,
            ind_type,
            f"[{tier_style}]{score}/100[/]",
            f"[{tier_style}]{tier}[/]",
            vt_text,
            vt_abuse_text,
            otx_text,
            tags_str,
        )

    console.print(table)


def export_json(results: List[Dict[str, Any]], filepath: Optional[str] = None):
    """Outputs results in formatted JSON."""
    json_str = json.dumps(results, indent=2)
    if filepath:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(json_str)
        console.print(f"[green][+] JSON results successfully written to: {filepath}[/green]")
    else:
        print(json_str)


def export_csv(results: List[Dict[str, Any]], filepath: Optional[str] = None):
    """Exports results to structured CSV."""
    headers = [
        "indicator",
        "type",
        "risk_score",
        "risk_tier",
        "vt_malicious",
        "vt_suspicious",
        "vt_total_engines",
        "abuse_confidence_score",
        "abuse_total_reports",
        "abuse_whitelisted",
        "otx_pulse_count",
        "tags",
        "enriched_at",
    ]

    rows = []
    for r in results:
        vt = r.get("sources", {}).get("virustotal", {})
        ab = r.get("sources", {}).get("abuseipdb", {})
        otx = r.get("sources", {}).get("alienvault_otx", {})

        rows.append({
            "indicator": r.get("indicator", ""),
            "type": r.get("type", ""),
            "risk_score": r.get("risk_score", 0),
            "risk_tier": r.get("risk_tier", ""),
            "vt_malicious": vt.get("malicious", 0) if vt.get("status") == "success" else "N/A",
            "vt_suspicious": vt.get("suspicious", 0) if vt.get("status") == "success" else "N/A",
            "vt_total_engines": vt.get("total_engines", 0) if vt.get("status") == "success" else "N/A",
            "abuse_confidence_score": ab.get("score", "N/A") if ab.get("status") == "success" else "N/A",
            "abuse_total_reports": ab.get("total_reports", "N/A") if ab.get("status") == "success" else "N/A",
            "abuse_whitelisted": ab.get("is_whitelisted", "N/A") if ab.get("status") == "success" else "N/A",
            "otx_pulse_count": otx.get("pulse_count", 0) if otx.get("status") == "success" else 0,
            "tags": ";".join(r.get("tags", [])),
            "enriched_at": r.get("enriched_at", ""),
        })

    if filepath:
        Path(filepath).parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()
            writer.writerows(rows)
        console.print(f"[green][+] CSV results successfully written to: {filepath}[/green]")
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)


# =============================================================================
# 7. Batch Ingestion Helper
# =============================================================================

def read_indicators_from_file(filepath: str) -> List[str]:
    """Reads indicators from CSV or plain-text file."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Input file '{filepath}' does not exist.")

    indicators: List[str] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        # Check if CSV
        if filepath.lower().endswith(".csv"):
            reader = csv.reader(f)
            header = next(reader, None)
            ind_col_idx = 0
            if header:
                for idx, col in enumerate(header):
                    if col.lower().strip() in ["indicator", "ioc", "ip", "domain", "hash", "url"]:
                        ind_col_idx = idx
                        break
                # If header was actual data rather than column name
                if detect_indicator_type(header[ind_col_idx]) != IndicatorType.UNKNOWN:
                    indicators.append(header[ind_col_idx].strip())

            for row in reader:
                if row and len(row) > ind_col_idx:
                    val = row[ind_col_idx].strip()
                    if val and not val.startswith("#"):
                        indicators.append(val)
        else:
            for line in f:
                val = line.strip()
                if val and not val.startswith("#"):
                    indicators.append(val)

    # Return deduplicated preserving order
    seen = set()
    deduped = []
    for item in indicators:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


# =============================================================================
# 8. Main CLI Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="ARZENS Production TI Enrichment Engine (VirusTotal v3, AbuseIPDB v2, AlienVault OTX v1)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--indicator", "-i", type=str, help="Single IOC indicator (IPv4, Domain, Hash, or URL)")
    input_group.add_argument("--input-file", "-f", type=str, help="Path to input file containing IOCs (.csv or .txt)")

    parser.add_argument("--config", "-c", type=str, default=DEFAULT_CONFIG_PATH, help="Path to config.yaml")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Output display format")
    parser.add_argument("--output", "-o", type=str, help="Optional output file path to write results (JSON or CSV)")
    parser.add_argument("--no-cache", action="store_true", help="Bypass local cache and force live API queries")
    parser.add_argument("--cache-ttl", type=float, default=24.0, help="Cache Time-To-Live in hours (default: 24.0)")

    args = parser.parse_args()

    # Banner
    console.print(Panel.fit(
        "[bold cyan]ARZENS Cyber Threat Intelligence Engine[/bold cyan]\n"
        "[dim]Multi-Feed Threat Enrichment, Rate Limiting & Normalized Scoring[/dim]",
        border_style="cyan"
    ))

    # Load Configuration
    config = load_config(args.config)

    # Initialize Cache Manager
    cache_enabled = not args.no_cache and config.get("cache", {}).get("enabled", True)
    cache_path = config.get("cache", {}).get("filepath", DEFAULT_CACHE_PATH)
    cache_mgr = CacheManager(filepath=cache_path, ttl_hours=args.cache_ttl, enabled=cache_enabled)

    # Initialize Engine
    engine = ThreatIntelEngine(config=config, cache_manager=cache_mgr)

    # Ingest Indicators
    indicators_to_process: List[str] = []
    if args.indicator:
        indicators_to_process.append(args.indicator.strip())
    elif args.input_file:
        try:
            indicators_to_process = read_indicators_from_file(args.input_file)
            console.print(f"[bold green][+] Ingested {len(indicators_to_process)} unique indicators from {args.input_file}[/bold green]")
        except Exception as e:
            console.print(f"[bold red]Error loading input file: {e}[/bold red]")
            sys.exit(1)

    # Process Enrichment Loop
    results: List[Dict[str, Any]] = []
    for idx, ind in enumerate(indicators_to_process, 1):
        if len(indicators_to_process) > 1:
            console.print(f"\n[bold white]({idx}/{len(indicators_to_process)}) Processing: {ind}[/bold white]")
        res = engine.enrich_indicator(ind, force_live=args.no_cache)
        results.append(res)

    # Render / Export Output
    console.print("\n")
    if args.format == "table" or (args.output and not args.format):
        render_terminal_table(results)

    if args.output:
        out_ext = Path(args.output).suffix.lower()
        if out_ext == ".json" or args.format == "json":
            export_json(results, args.output)
        elif out_ext == ".csv" or args.format == "csv":
            export_csv(results, args.output)
        else:
            # Default to json if unstated
            export_json(results, args.output)
    else:
        if args.format == "json":
            export_json(results)
        elif args.format == "csv":
            export_csv(results)


if __name__ == "__main__":
    main()
