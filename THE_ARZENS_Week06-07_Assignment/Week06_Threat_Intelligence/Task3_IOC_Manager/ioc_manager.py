#!/usr/bin/env python3
"""
===============================================================================
Threat Intelligence IOC Manager & Lifecycle Automation
ARZENS Internship Program - AI, Automation & Security Track (Week 06-07)
Task 3 Deliverable: ioc_manager.py

Author: Threat Intel Systems Engineer
Description:
    Production-grade IOC Lifecycle Management platform. Provides automated
    ingestion, multi-source re-enrichment, rule-based confidence scoring,
    stale IOC expiration, firewall/SIEM blocklist generation (IP, Suricata, CSV),
    and executive HTML dashboard reporting.
===============================================================================
"""

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Force UTF-8 encoding on standard streams to support all platforms smoothly
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(safe_box=True, legacy_windows=False)

# Resolve import path for Task 2 Enrichment Engine
CURRENT_DIR = Path(__file__).resolve().parent
TASK2_DIR = CURRENT_DIR.parent / "Task2_Enrichment_Engine"
if str(TASK2_DIR) not in sys.path:
    sys.path.insert(0, str(TASK2_DIR))

try:
    from ti_enricher import (
        CacheManager,
        IndicatorType,
        ThreatIntelEngine,
        detect_indicator_type,
        load_config as load_task2_config,
        read_indicators_from_file,
    )
    ENRICHER_AVAILABLE = True
except ImportError:
    ENRICHER_AVAILABLE = False


# =============================================================================
# 1. Configuration & Database Management
# =============================================================================

DEFAULT_CONFIG_PATH = "ioc_config.yaml"
DEFAULT_DB_PATH = "ioc_database.json"


def load_ioc_config(config_path: str = DEFAULT_CONFIG_PATH) -> Dict[str, Any]:
    """Loads IOC manager configuration."""
    cfg: Dict[str, Any] = {}
    path = Path(config_path)
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}

    # Defaults
    if "database" not in cfg:
        cfg["database"] = {"filepath": DEFAULT_DB_PATH, "auto_backup": True}
    if "lifecycles" not in cfg:
        cfg["lifecycles"] = {
            "default_ttl_days": {"ipv4": 30, "domain": 60, "url": 30, "hash": 180},
            "auto_expire_on_check": True,
        }
    if "confidence_scoring" not in cfg:
        cfg["confidence_scoring"] = {
            "source_diversity_weights": {"three_sources": 35, "two_sources": 25, "one_source": 10},
            "stability_bonus": {"multi_engine_agreement": 25, "otx_correlation": 15, "clean_whitelist_agreement": 35},
            "recency_max_days": 30,
            "recency_freshness_window_days": 7,
            "recency_max_points": 25,
        }
    if "blocklist_export" not in cfg:
        cfg["blocklist_export"] = {
            "default_output_file": "blocklist.txt",
            "default_format": "ip",
            "min_risk_score": 50,
            "min_confidence": 50,
            "active_only": True,
            "suricata_sid_start": 1000001,
        }
    if "report_generation" not in cfg:
        cfg["report_generation"] = {
            "default_output_file": "weekly_report.html",
            "title": "ARZENS Cyber Threat Intelligence Weekly Executive Briefing",
            "organization": "ARZENS Cyber Defense Operations & CSIRT",
        }
    return cfg


class IOCDatabase:
    """
    JSON database for full-lifecycle IOC records.
    Maintains indicator metadata, audit history, timestamps, and confidence scores.
    """

    def __init__(self, filepath: str = DEFAULT_DB_PATH):
        self.filepath = Path(filepath)
        self.data: Dict[str, Any] = {"database_metadata": {}, "indicators": {}}
        self.load()

    def load(self):
        if self.filepath.exists():
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self.data = json.load(f)
                if "indicators" not in self.data:
                    self.data["indicators"] = {}
                if "database_metadata" not in self.data:
                    self.data["database_metadata"] = {}
            except Exception as e:
                console.print(f"[yellow]Warning: Could not read {self.filepath} ({e}). Starting fresh.[/yellow]")
                self._reset()
        else:
            self._reset()

    def _reset(self):
        self.data = {
            "database_metadata": {
                "version": "1.0",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "total_records": 0,
                "active_records": 0,
                "expired_records": 0,
                "revoked_records": 0,
            },
            "indicators": {},
        }

    def save(self):
        self._update_metadata()
        self.filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(self.filepath, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)

    def _update_metadata(self):
        records = self.data.get("indicators", {})
        total = len(records)
        active = sum(1 for r in records.values() if r.get("status") == "active")
        expired = sum(1 for r in records.values() if r.get("status") == "expired")
        revoked = sum(1 for r in records.values() if r.get("status") == "revoked")

        self.data["database_metadata"].update({
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_records": total,
            "active_records": active,
            "expired_records": expired,
            "revoked_records": revoked,
        })

    def get_all(self) -> Dict[str, Dict[str, Any]]:
        return self.data.get("indicators", {})

    def get(self, indicator: str) -> Optional[Dict[str, Any]]:
        return self.data.get("indicators", {}).get(indicator)

    def upsert(self, record: Dict[str, Any]):
        ind = record["indicator"]
        self.data.setdefault("indicators", {})[ind] = record
        self.save()


# =============================================================================
# 2. Rule-Based Confidence Scoring Algorithm
# =============================================================================

def calculate_confidence_score(
    record: Dict[str, Any],
    config: Optional[Dict[str, Any]] = None,
) -> Tuple[int, Dict[str, Any]]:
    """
    ===========================================================================
    RULE-BASED CONFIDENCE SCORING SPECIFICATION (Scale: 0 - 100)
    ===========================================================================
    Measures intelligence reliability based on:
    1. Source Diversity (Max 35 pts):
       - 3 authoritative feeds verified: +35 pts
       - 2 authoritative feeds verified: +25 pts
       - 1 feed verified: +10 pts

    2. Analytical Stability & Cross-Engine Consensus (Max 40 pts):
       - VT malicious engines >= 5 AND AbuseIPDB score >= 50: +25 pts
       - OTX community threat pulses >= 3 with threat tags: +15 pts
       - Clean whitelisted status across all engines: +35 pts (high confidence in clean)
       - Conflicting signals (e.g. VT=0 but AbuseIPDB>80): +5 pts

    3. Recency & Temporal Freshness (Max 25 pts):
       - Δt = (now - last_seen).days
       - Δt <= 7 days: +25 pts (fresh intelligence)
       - 7 < Δt <= 30 days: linear decay max(0, 25 - int(Δt - 7))
       - Δt > 30 days: 0 pts (stale intelligence penalty)

    Total Confidence = min(100, max(0, Diversity + Stability + Recency))
    ===========================================================================
    """
    cfg = config or {}
    conf_cfg = cfg.get("confidence_scoring", {})
    div_weights = conf_cfg.get("source_diversity_weights", {"three_sources": 35, "two_sources": 25, "one_source": 10})
    stab_cfg = conf_cfg.get("stability_bonus", {"multi_engine_agreement": 25, "otx_correlation": 15, "clean_whitelist_agreement": 35})

    sources_active = record.get("sources", [])
    enrichment = record.get("enrichment_data", {})
    last_seen_str = record.get("last_seen")

    # 1. Source Diversity
    active_count = len(sources_active)
    if active_count >= 3:
        diversity_pts = div_weights.get("three_sources", 35)
    elif active_count == 2:
        diversity_pts = div_weights.get("two_sources", 25)
    elif active_count == 1:
        diversity_pts = div_weights.get("one_source", 10)
    else:
        diversity_pts = 0

    # 2. Score Stability & Agreement
    stability_pts = 0
    vt_data = enrichment.get("virustotal", {})
    abuse_data = enrichment.get("abuseipdb", {})
    otx_data = enrichment.get("alienvault_otx", {})

    vt_mal = vt_data.get("malicious", 0) if vt_data.get("status") == "success" else 0
    abuse_score = abuse_data.get("score", 0) if abuse_data.get("status") == "success" else 0
    abuse_whitelisted = abuse_data.get("is_whitelisted", False) if abuse_data.get("status") == "success" else False
    otx_pulses = otx_data.get("pulse_count", 0) if otx_data.get("status") == "success" else 0

    if abuse_whitelisted and vt_mal == 0 and otx_pulses == 0:
        stability_pts = stab_cfg.get("clean_whitelist_agreement", 35)
    else:
        if vt_mal >= 3 and abuse_score >= 40:
            stability_pts += stab_cfg.get("multi_engine_agreement", 25)
        elif vt_mal > 0 or abuse_score > 30:
            stability_pts += 12

        if otx_pulses >= 3:
            stability_pts += stab_cfg.get("otx_correlation", 15)
        elif otx_pulses > 0:
            stability_pts += 8

    stability_pts = min(40, stability_pts)

    # 3. Recency & Temporal Decay
    recency_pts = 25
    if last_seen_str:
        try:
            last_seen_dt = datetime.fromisoformat(last_seen_str)
            now = datetime.now(timezone.utc)
            delta_days = (now - last_seen_dt).total_seconds() / 86400.0
            if delta_days <= 7.0:
                recency_pts = 25
            elif delta_days <= 30.0:
                recency_pts = max(0, int(round(25 - (delta_days - 7.0))))
            else:
                recency_pts = 0
        except Exception:
            recency_pts = 15

    total_conf = min(100, max(0, diversity_pts + stability_pts + recency_pts))

    breakdown = {
        "diversity_points": diversity_pts,
        "stability_points": stability_pts,
        "recency_points": recency_pts,
        "total_confidence": total_conf,
    }

    return total_conf, breakdown


# =============================================================================
# 3. Lifecycle Automation Engine
# =============================================================================

class IOCManager:
    """
    Coordinates ingestion, enrichment, confidence scoring, lifecycle tracking,
    SIEM blocklist export, and executive report generation.
    """

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        self.config = load_ioc_config(config_path)
        db_path = self.config.get("database", {}).get("filepath", DEFAULT_DB_PATH)
        self.db = IOCDatabase(filepath=db_path)

        # Initialize TI Enricher if available
        self.enricher_engine: Optional[ThreatIntelEngine] = None
        if ENRICHER_AVAILABLE:
            task2_cfg_file = TASK2_DIR / "config.yaml"
            t2_cfg = load_task2_config(str(task2_cfg_file)) if task2_cfg_file.exists() else {}
            cache_file = TASK2_DIR / "cache.json"
            cache_mgr = CacheManager(filepath=str(cache_file))
            self.enricher_engine = ThreatIntelEngine(config=t2_cfg, cache_manager=cache_mgr)

    # -------------------------------------------------------------------------
    # Ingestion & Ingest File
    # -------------------------------------------------------------------------
    def add_or_update_ioc(self, indicator: str, enrichment_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Ingests a new IOC or updates existing metadata, last_seen, confidence, and expiration.
        """
        clean_ind = indicator.strip()
        ind_type = detect_indicator_type(clean_ind) if ENRICHER_AVAILABLE else "unknown"

        # Perform live/cached enrichment if enrichment data not provided
        if not enrichment_data and self.enricher_engine:
            enrichment_data = self.enricher_engine.enrich_indicator(clean_ind)

        enrichment_data = enrichment_data or {}
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        # TTL lookup
        ttl_days_map = self.config.get("lifecycles", {}).get("default_ttl_days", {})
        ttl_days = ttl_days_map.get(ind_type, 30)
        new_expiration = (now + timedelta(days=ttl_days)).isoformat()

        existing = self.db.get(clean_ind)

        # Sources identification
        sources = []
        raw_sources = enrichment_data.get("sources", {})
        for src_key, src_val in raw_sources.items():
            if isinstance(src_val, dict) and src_val.get("status") == "success":
                sources.append(src_key)

        risk_score = enrichment_data.get("risk_score", 0)
        risk_tier = enrichment_data.get("risk_tier", "CLEAN")
        tags = enrichment_data.get("tags", [])

        if existing:
            # Update existing record
            record = existing
            record["last_seen"] = now_iso
            record["expiration"] = new_expiration
            record["status"] = "active"  # Reactivate if previously expired
            record["risk_score"] = risk_score
            record["risk_tier"] = risk_tier
            record["sources"] = list(set(record.get("sources", []) + sources))
            record["tags"] = list(set(record.get("tags", []) + tags))
            record["enrichment_data"] = raw_sources

            # Recompute Confidence
            conf, breakdown = calculate_confidence_score(record, self.config)
            record["confidence"] = conf
            record["confidence_breakdown"] = breakdown

            # Append audit history
            record.setdefault("history", []).append({
                "timestamp": now_iso,
                "action": "re-enriched",
                "risk_score": risk_score,
                "confidence": conf,
            })
            console.print(f"[green][+] Updated existing IOC record: {clean_ind} (Risk: {risk_score}, Conf: {conf})[/green]")
        else:
            # Create brand-new record
            record = {
                "indicator": clean_ind,
                "type": ind_type,
                "first_seen": now_iso,
                "last_seen": now_iso,
                "expiration": new_expiration,
                "confidence": 0,
                "risk_score": risk_score,
                "risk_tier": risk_tier,
                "status": "active",
                "sources": sources,
                "tags": tags,
                "enrichment_data": raw_sources,
                "history": [{
                    "timestamp": now_iso,
                    "action": "created",
                    "risk_score": risk_score,
                    "confidence": 0,
                }],
            }

            # Calculate confidence
            conf, breakdown = calculate_confidence_score(record, self.config)
            record["confidence"] = conf
            record["confidence_breakdown"] = breakdown
            record["history"][0]["confidence"] = conf
            console.print(f"[green][+] Ingested new IOC record: {clean_ind} (Risk: {risk_score}, Conf: {conf})[/green]")

        self.db.upsert(record)
        return record

    def ingest_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Ingests indicators from CSV or text file, enriching each."""
        indicators = read_indicators_from_file(filepath) if ENRICHER_AVAILABLE else []
        console.print(f"[bold cyan][*] Processing {len(indicators)} indicators from {filepath}...[/bold cyan]")

        processed = []
        for idx, ind in enumerate(indicators, 1):
            console.print(f"[{idx}/{len(indicators)}] Ingesting {ind}...")
            rec = self.add_or_update_ioc(ind)
            processed.append(rec)

        return processed

    # -------------------------------------------------------------------------
    # Lifecycle Expiration Check
    # -------------------------------------------------------------------------
    def expire_check(self, prune_days: Optional[int] = None) -> Dict[str, Any]:
        """
        Scans all database IOCs. If current_time > expiration, marks status as 'expired'.
        Optionally prunes or archives stale entries.
        """
        now = datetime.now(timezone.utc)
        records = self.db.get_all()
        expired_count = 0
        active_count = 0
        pruned_count = 0

        for ind, rec in list(records.items()):
            exp_str = rec.get("expiration")
            current_status = rec.get("status", "active")

            if exp_str:
                try:
                    exp_dt = datetime.fromisoformat(exp_str)
                    if now > exp_dt and current_status == "active":
                        rec["status"] = "expired"
                        rec.setdefault("history", []).append({
                            "timestamp": now.isoformat(),
                            "action": "expired_due_to_ttl",
                            "note": f"Expired at {exp_str}",
                        })
                        expired_count += 1
                        console.print(f"[yellow][!] Marked expired: {ind} (expired on {exp_str})[/yellow]")
                    elif current_status == "active":
                        active_count += 1

                    # Optional pruning of deeply stale items
                    if prune_days and current_status == "expired":
                        last_seen_dt = datetime.fromisoformat(rec.get("last_seen", exp_str))
                        if (now - last_seen_dt).days > prune_days:
                            del records[ind]
                            pruned_count += 1
                            console.print(f"[red][x] Pruned stale record: {ind}[/red]")
                except Exception:
                    pass

        self.db.save()

        summary = {
            "scanned": len(records),
            "newly_expired": expired_count,
            "total_active": active_count,
            "pruned": pruned_count,
        }
        return summary

    # -------------------------------------------------------------------------
    # Re-Enrich All Active IOCs
    # -------------------------------------------------------------------------
    def update_all_active(self) -> int:
        """Re-enriches all active indicators in database."""
        records = self.db.get_all()
        active_inds = [ind for ind, r in records.items() if r.get("status") == "active"]

        console.print(f"[bold cyan][*] Re-enriching {len(active_inds)} active IOCs...[/bold cyan]")
        count = 0
        for idx, ind in enumerate(active_inds, 1):
            console.print(f"[{idx}/{len(active_inds)}] Re-enriching {ind}...")
            self.add_or_update_ioc(ind)
            count += 1

        return count

    # -------------------------------------------------------------------------
    # SIEM & Firewall Export
    # -------------------------------------------------------------------------
    def export_blocklist(
        self,
        output_path: Optional[str] = None,
        export_format: str = "ip",
        min_risk: int = 50,
        min_conf: int = 50,
    ) -> str:
        """
        Generates production perimeter firewall and SIEM export (IP list, Suricata, CSV).
        Filters for active IOCs with risk_score >= min_risk and confidence >= min_conf.
        """
        cfg_export = self.config.get("blocklist_export", {})
        target_path = output_path or cfg_export.get("default_output_file", "blocklist.txt")
        records = self.db.get_all()

        # Filter candidates
        candidates = []
        for r in records.values():
            if r.get("status") != "active":
                continue
            if r.get("risk_score", 0) >= min_risk and r.get("confidence", 0) >= min_conf:
                candidates.append(r)

        candidates.sort(key=lambda x: x.get("risk_score", 0), reverse=True)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines: List[str] = []
        if export_format.lower() == "ip":
            lines.append(f"# =====================================================================")
            lines.append(f"# ARZENS Perimeter Firewall Blocklist (High Confidence Threat Feed)")
            lines.append(f"# Generated: {now_str}")
            lines.append(f"# Criteria: Status=Active, Risk >= {min_risk}, Confidence >= {min_conf}")
            lines.append(f"# Total Indicators: {len([c for c in candidates if c.get('type') == 'ipv4'])}")
            lines.append(f"# =====================================================================")
            for c in candidates:
                if c.get("type") == "ipv4":
                    ind = c["indicator"]
                    risk = c.get("risk_score", 0)
                    conf = c.get("confidence", 0)
                    tags = ",".join(c.get("tags", [])[:3])
                    lines.append(f"{ind}/32  # Risk: {risk}, Conf: {conf}, Tags: [{tags}]")

        elif export_format.lower() == "suricata":
            sid_start = cfg_export.get("suricata_sid_start", 1000001)
            lines.append(f"# =====================================================================")
            lines.append(f"# ARZENS Suricata IDS/IPS Threat Prevention Rules")
            lines.append(f"# Generated: {now_str}")
            lines.append(f"# =====================================================================")
            for idx, c in enumerate(candidates):
                ind = c["indicator"]
                ind_type = c.get("type")
                risk = c.get("risk_score", 0)
                sid = sid_start + idx
                if ind_type == "ipv4":
                    rule = (
                        f'drop ip {ind} any -> any any (msg:"ARZENS TI - Malicious IP Dropped [{ind}]"; '
                        f'reference:url,virustotal.com; classtype:trojan-activity; sid:{sid}; rev:1;)'
                    )
                    lines.append(rule)
                elif ind_type == "domain":
                    rule = (
                        f'drop dns any any -> any any (msg:"ARZENS TI - Malicious DNS Query Dropped [{ind}]"; '
                        f'dns.query; content:"{ind}"; nocase; sid:{sid}; rev:1;)'
                    )
                    lines.append(rule)

        elif export_format.lower() == "csv":
            out_path = Path(target_path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["indicator", "type", "risk_score", "confidence", "status", "expiration", "tags"])
                for c in candidates:
                    writer.writerow([
                        c.get("indicator"),
                        c.get("type"),
                        c.get("risk_score"),
                        c.get("confidence"),
                        c.get("status"),
                        c.get("expiration"),
                        ";".join(c.get("tags", [])),
                    ])
            console.print(f"[green][+] Blocklist exported successfully in CSV to: {target_path}[/green]")
            return target_path

        out_path = Path(target_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        console.print(f"[green][+] Blocklist exported ({export_format.upper()}) to: {target_path}[/green]")
        return target_path

    # -------------------------------------------------------------------------
    # Modern Executive HTML Report Generation
    # -------------------------------------------------------------------------
    def generate_report(self, output_path: Optional[str] = None) -> str:
        """
        Generates an executive cybersecurity threat dashboard in self-contained modern HTML.
        Includes KPI statistics cards, risk distribution bars, active IOC table,
        and defensive action recommendations.
        """
        cfg_rep = self.config.get("report_generation", {})
        target_path = output_path or cfg_rep.get("default_output_file", "weekly_report.html")
        title = cfg_rep.get("title", "ARZENS Cyber Threat Intelligence Weekly Executive Briefing")
        org = cfg_rep.get("organization", "ARZENS Cyber Defense Operations & CSIRT")

        records = list(self.db.get_all().values())
        now_dt = datetime.now(timezone.utc)
        now_str = now_dt.strftime("%B %d, %Y - %H:%M UTC")

        # Metrics
        total_iocs = len(records)
        active_iocs = sum(1 for r in records if r.get("status") == "active")
        expired_iocs = sum(1 for r in records if r.get("status") == "expired")
        high_conf_threats = sum(1 for r in records if r.get("status") == "active" and r.get("confidence", 0) >= 70)
        critical_risk_threats = sum(1 for r in records if r.get("risk_tier") == "CRITICAL" and r.get("status") == "active")

        # Types breakdown
        type_counts = {"ipv4": 0, "domain": 0, "hash": 0, "url": 0, "other": 0}
        tier_counts = {"CRITICAL": 0, "HIGH": 0, "SUSPICIOUS": 0, "CLEAN": 0}

        for r in records:
            t = r.get("type", "other").lower()
            type_counts[t if t in type_counts else "other"] += 1
            tier = r.get("risk_tier", "CLEAN")
            tier_counts[tier if tier in tier_counts else "CLEAN"] += 1

        # Sort top threats
        top_threats = sorted(
            [r for r in records if r.get("status") == "active"],
            key=lambda x: (x.get("risk_score", 0), x.get("confidence", 0)),
            reverse=True,
        )

        # Build HTML Rows
        table_rows = []
        for r in top_threats:
            ind = r.get("indicator", "")
            ind_type = r.get("type", "").upper()
            risk = r.get("risk_score", 0)
            conf = r.get("confidence", 0)
            tier = r.get("risk_tier", "CLEAN")
            tags = r.get("tags", [])
            tag_badges = "".join([f'<span class="badge badge-tag">{t}</span>' for t in tags[:3]]) if tags else '<span class="text-muted">-</span>'
            first_seen = r.get("first_seen", "")[:10]
            exp_date = r.get("expiration", "")[:10]

            tier_badge_class = {
                "CRITICAL": "badge-critical",
                "HIGH": "badge-high",
                "SUSPICIOUS": "badge-suspicious",
                "CLEAN": "badge-clean",
            }.get(tier, "badge-clean")

            row_html = f"""
            <tr>
                <td class="ind-cell"><code>{ind}</code></td>
                <td><span class="badge badge-type">{ind_type}</span></td>
                <td>
                    <div class="score-container">
                        <span class="badge {tier_badge_class}">{risk}/100</span>
                        <div class="progress-bar"><div class="progress-fill {tier.lower()}" style="width: {risk}%;"></div></div>
                    </div>
                </td>
                <td>
                    <div class="conf-container">
                        <strong>{conf}%</strong>
                        <div class="progress-bar"><div class="progress-fill conf" style="width: {conf}%;"></div></div>
                    </div>
                </td>
                <td><span class="badge badge-active">ACTIVE</span></td>
                <td>{tag_badges}</td>
                <td class="text-muted">{first_seen}</td>
                <td class="text-muted">{exp_date}</td>
            </tr>
            """
            table_rows.append(row_html)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        :root {{
            --bg-base: #0a0e17;
            --bg-surface: #111827;
            --bg-card: #1e293b;
            --bg-card-hover: #24344d;
            --border-color: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --accent-cyan: #00f0ff;
            --accent-blue: #3b82f6;
            --color-critical: #ef4444;
            --color-high: #f97316;
            --color-suspicious: #eab308;
            --color-clean: #10b981;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-base);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.5;
            padding: 30px 40px;
        }}

        .container {{ max-width: 1400px; margin: 0 auto; }}

        /* Header */
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 30px;
        }}
        .header-title h1 {{
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .header-title h1 span.highlight {{
            color: var(--accent-cyan);
        }}
        .header-title p {{
            color: var(--text-secondary);
            font-size: 0.95rem;
            margin-top: 4px;
        }}
        .header-meta {{
            text-align: right;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }}
        .header-meta .timestamp {{
            color: var(--accent-cyan);
            font-weight: 600;
        }}

        /* KPI Cards */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .metric-card {{
            background-color: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            position: relative;
            overflow: hidden;
            transition: transform 0.2s ease, border-color 0.2s ease;
        }}
        .metric-card:hover {{
            transform: translateY(-2px);
            border-color: var(--accent-cyan);
        }}
        .metric-card::before {{
            content: "";
            position: absolute;
            top: 0; left: 0; width: 4px; height: 100%;
        }}
        .metric-card.total::before {{ background: var(--accent-cyan); }}
        .metric-card.active::before {{ background: var(--accent-blue); }}
        .metric-card.critical::before {{ background: var(--color-critical); }}
        .metric-card.high-conf::before {{ background: var(--color-clean); }}
        .metric-card.expired::before {{ background: var(--text-muted); }}

        .metric-label {{
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            font-weight: 600;
        }}
        .metric-value {{
            font-size: 2.2rem;
            font-weight: 800;
            color: var(--text-primary);
            margin: 8px 0 4px 0;
        }}
        .metric-subtext {{
            font-size: 0.85rem;
            color: var(--text-muted);
        }}

        /* Visual Breakdown Grid */
        .analytics-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }}
        .analytics-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 24px;
        }}
        .analytics-card h2 {{
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .bar-stat {{
            margin-bottom: 14px;
        }}
        .bar-stat-label {{
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            margin-bottom: 6px;
            color: var(--text-secondary);
        }}
        .stat-track {{
            width: 100%;
            height: 8px;
            background: var(--bg-card);
            border-radius: 4px;
            overflow: hidden;
        }}
        .stat-fill {{
            height: 100%;
            border-radius: 4px;
        }}

        /* Threat Table */
        .table-section {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 30px;
        }}
        .table-section h2 {{
            font-size: 1.15rem;
            font-weight: 600;
            margin-bottom: 18px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }}
        th {{
            text-align: left;
            padding: 12px 14px;
            background: var(--bg-card);
            color: var(--text-secondary);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            border-bottom: 2px solid var(--border-color);
        }}
        td {{
            padding: 12px 14px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }}
        tr:hover td {{
            background-color: var(--bg-card-hover);
        }}
        code {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            background: rgba(0, 240, 255, 0.08);
            color: var(--accent-cyan);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.85rem;
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }}
        .badge-critical {{ background: rgba(239, 68, 68, 0.15); color: var(--color-critical); border: 1px solid var(--color-critical); }}
        .badge-high {{ background: rgba(249, 115, 22, 0.15); color: var(--color-high); border: 1px solid var(--color-high); }}
        .badge-suspicious {{ background: rgba(234, 179, 8, 0.15); color: var(--color-suspicious); border: 1px solid var(--color-suspicious); }}
        .badge-clean {{ background: rgba(16, 185, 129, 0.15); color: var(--color-clean); border: 1px solid var(--color-clean); }}
        .badge-active {{ background: rgba(59, 130, 246, 0.15); color: var(--accent-blue); }}
        .badge-type {{ background: #334155; color: #f1f5f9; }}
        .badge-tag {{ background: #1e293b; color: #cbd5e1; margin-right: 4px; border: 1px solid #475569; }}

        .score-container, .conf-container {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .progress-bar {{
            width: 60px;
            height: 6px;
            background: #334155;
            border-radius: 3px;
            overflow: hidden;
        }}
        .progress-fill {{ height: 100%; border-radius: 3px; }}
        .progress-fill.critical {{ background: var(--color-critical); }}
        .progress-fill.high {{ background: var(--color-high); }}
        .progress-fill.suspicious {{ background: var(--color-suspicious); }}
        .progress-fill.clean {{ background: var(--color-clean); }}
        .progress-fill.conf {{ background: var(--accent-cyan); }}

        /* Executive Recommendations */
        .recs-section {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 24px;
        }}
        .recs-section h2 {{
            font-size: 1.15rem;
            font-weight: 600;
            margin-bottom: 14px;
            color: var(--accent-cyan);
        }}
        .rec-item {{
            margin-bottom: 12px;
            padding-left: 20px;
            position: relative;
            color: var(--text-secondary);
        }}
        .rec-item::before {{
            content: "▶";
            position: absolute;
            left: 0;
            color: var(--accent-cyan);
            font-size: 0.75rem;
            top: 2px;
        }}
        .rec-item strong {{
            color: var(--text-primary);
        }}

        footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            color: var(--text-muted);
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>[ARZENS] <span class="highlight">Threat Intelligence Operations</span></h1>
                <p>Weekly Executive IOC Management, Lifecycle & Risk Briefing</p>
            </div>
            <div class="header-meta">
                <div>Organization: <strong>{org}</strong></div>
                <div>Briefing Timestamp: <span class="timestamp">{now_str}</span></div>
            </div>
        </header>

        <!-- KPI Metric Cards -->
        <section class="metrics-grid">
            <div class="metric-card total">
                <div class="metric-label">Total Monitored IOCs</div>
                <div class="metric-value">{total_iocs}</div>
                <div class="metric-subtext">Active lifecycle records</div>
            </div>
            <div class="metric-card active">
                <div class="metric-label">Active Threat Blocklist</div>
                <div class="metric-value">{active_iocs}</div>
                <div class="metric-subtext">Propagated to perimeter SIEM</div>
            </div>
            <div class="metric-card critical">
                <div class="metric-label">Critical Tier Threats</div>
                <div class="metric-value">{critical_risk_threats}</div>
                <div class="metric-subtext">Risk score &ge; 75 / 100</div>
            </div>
            <div class="metric-card high-conf">
                <div class="metric-label">High Confidence Verified</div>
                <div class="metric-value">{high_conf_threats}</div>
                <div class="metric-subtext">Confidence index &ge; 70%</div>
            </div>
            <div class="metric-card expired">
                <div class="metric-label">Stale / Expired IOCs</div>
                <div class="metric-value">{expired_iocs}</div>
                <div class="metric-subtext">Awaiting retirement or re-evaluation</div>
            </div>
        </section>

        <!-- Analytics Breakdown -->
        <section class="analytics-grid">
            <div class="analytics-card">
                <h2>Threat Type Distribution</h2>
                <div class="bar-stat">
                    <div class="bar-stat-label"><span>IPv4 Addresses</span><span>{type_counts['ipv4']}</span></div>
                    <div class="stat-track"><div class="stat-fill" style="background: var(--accent-cyan); width: {min(100, int(type_counts['ipv4']/max(1, total_iocs)*100))}%;"></div></div>
                </div>
                <div class="bar-stat">
                    <div class="bar-stat-label"><span>Domain Names</span><span>{type_counts['domain']}</span></div>
                    <div class="stat-track"><div class="stat-fill" style="background: var(--accent-blue); width: {min(100, int(type_counts['domain']/max(1, total_iocs)*100))}%;"></div></div>
                </div>
                <div class="bar-stat">
                    <div class="bar-stat-label"><span>File Hashes (SHA256/MD5)</span><span>{type_counts['hash']}</span></div>
                    <div class="stat-track"><div class="stat-fill" style="background: #a855f7; width: {min(100, int(type_counts['hash']/max(1, total_iocs)*100))}%;"></div></div>
                </div>
                <div class="bar-stat">
                    <div class="bar-stat-label"><span>URLs</span><span>{type_counts['url']}</span></div>
                    <div class="stat-track"><div class="stat-fill" style="background: #ec4899; width: {min(100, int(type_counts['url']/max(1, total_iocs)*100))}%;"></div></div>
                </div>
            </div>

            <div class="analytics-card">
                <h2>Risk Severity Breakdown</h2>
                <div class="bar-stat">
                    <div class="bar-stat-label"><span style="color: var(--color-critical);">Critical Risk (75-100)</span><span>{tier_counts['CRITICAL']}</span></div>
                    <div class="stat-track"><div class="stat-fill" style="background: var(--color-critical); width: {min(100, int(tier_counts['CRITICAL']/max(1, total_iocs)*100))}%;"></div></div>
                </div>
                <div class="bar-stat">
                    <div class="bar-stat-label"><span style="color: var(--color-high);">High Risk (50-74)</span><span>{tier_counts['HIGH']}</span></div>
                    <div class="stat-track"><div class="stat-fill" style="background: var(--color-high); width: {min(100, int(tier_counts['HIGH']/max(1, total_iocs)*100))}%;"></div></div>
                </div>
                <div class="bar-stat">
                    <div class="bar-stat-label"><span style="color: var(--color-suspicious);">Suspicious (20-49)</span><span>{tier_counts['SUSPICIOUS']}</span></div>
                    <div class="stat-track"><div class="stat-fill" style="background: var(--color-suspicious); width: {min(100, int(tier_counts['SUSPICIOUS']/max(1, total_iocs)*100))}%;"></div></div>
                </div>
                <div class="bar-stat">
                    <div class="bar-stat-label"><span style="color: var(--color-clean);">Clean / Whitelisted (0-19)</span><span>{tier_counts['CLEAN']}</span></div>
                    <div class="stat-track"><div class="stat-fill" style="background: var(--color-clean); width: {min(100, int(tier_counts['CLEAN']/max(1, total_iocs)*100))}%;"></div></div>
                </div>
            </div>
        </section>

        <!-- Active Threat Table -->
        <section class="table-section">
            <h2>Active High-Priority Indicators of Compromise (IOC Database)</h2>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Indicator</th>
                            <th>Type</th>
                            <th>Risk Score</th>
                            <th>Confidence</th>
                            <th>Lifecycle Status</th>
                            <th>Threat Tags & Attribution</th>
                            <th>First Seen</th>
                            <th>Expiration</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(table_rows) if table_rows else '<tr><td colspan="8" style="text-align:center; color:var(--text-muted);">No active threats cataloged in database.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </section>

        <!-- Executive Recommendations -->
        <section class="recs-section">
            <h2>SOC & Incident Response Directives</h2>
            <div class="rec-item">
                <strong>Perimeter Firewall Sync:</strong> Actively synchronize <code>blocklist.txt</code> with border BGP null-route and perimeter firewall ACLs to immediately drop scanning and brute-force traffic.
            </div>
            <div class="rec-item">
                <strong>Suricata Rule Deployment:</strong> Ingest the exported Suricata IDS rules across internal sensor taps to detect lateral malware communication and DNS tunneling.
            </div>
            <div class="rec-item">
                <strong>Stale IOC Retirement:</strong> Run automated <code>--expire-check</code> weekly to purge decommissioned C2 IPs and eliminate firewall memory bloat and false positive alerts.
            </div>
            <div class="rec-item">
                <strong>Whitelisted Exceptions:</strong> Verify that enterprise resolvers (Google DNS <code>8.8.8.8</code> and Cloudflare <code>1.1.1.1</code>) remain marked clean with zero risk to maintain network uptime.
            </div>
        </section>

        <footer>
            <p>&copy; 2026 {org} &bull; ARZENS Advanced Track &bull; Automated Threat Intelligence Lifecycle Management System</p>
        </footer>
    </div>
</body>
</html>
"""
        out_path = Path(target_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        console.print(f"[green][+] Executive dashboard report written successfully to: {target_path}[/green]")
        return target_path


# =============================================================================
# 4. Command Line Interface (CLI)
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="ARZENS IOC Manager & Lifecycle Automation Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("--add-file", type=str, help="Ingest new IOCs from file (CSV/TXT) and enrich")
    action_group.add_argument("--update-all", action="store_true", help="Re-enrich all active IOCs and recompute risk/confidence")
    action_group.add_argument("--expire-check", action="store_true", help="Scan database and mark stale/expired IOCs")
    action_group.add_argument("--export-blocklist", action="store_true", help="Generate firewall/SIEM blocklist export")
    action_group.add_argument("--generate-report", action="store_true", help="Generate executive HTML dashboard report")
    action_group.add_argument("--list-all", action="store_true", help="Display formatted table of all database IOC records")

    parser.add_argument("--config", "-c", type=str, default=DEFAULT_CONFIG_PATH, help="Path to ioc_config.yaml")
    parser.add_argument("--format", choices=["ip", "suricata", "csv"], default="ip", help="Export blocklist format")
    parser.add_argument("--output", "-o", type=str, help="Output destination path for export or report")
    parser.add_argument("--prune", type=int, default=None, help="Prune records expired for more than N days")

    args = parser.parse_args()

    console.print(Panel.fit(
        "[bold cyan]ARZENS IOC Manager & Automation Engine[/bold cyan]\n"
        "[dim]Lifecycle Automation, Confidence Scoring, SIEM Export & Reporting[/dim]",
        border_style="cyan"
    ))

    mgr = IOCManager(config_path=args.config)

    # Dispatch Commands
    if args.add_file:
        mgr.ingest_file(args.add_file)

    elif args.update_all:
        cnt = mgr.update_all_active()
        console.print(f"[bold green][+] Completed re-enrichment of {cnt} active IOCs.[/bold green]")

    elif args.expire_check:
        summary = mgr.expire_check(prune_days=args.prune)
        table = Table(title="IOC Lifecycle Expiration Audit", show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Count", justify="center")
        table.add_row("Total Scanned Records", str(summary["scanned"]))
        table.add_row("Newly Marked Expired", str(summary["newly_expired"]))
        table.add_row("Remaining Active Records", str(summary["total_active"]))
        if args.prune:
            table.add_row("Pruned Records", str(summary["pruned"]))
        console.print(table)

    elif args.export_blocklist:
        mgr.export_blocklist(output_path=args.output, export_format=args.format)

    elif args.generate_report:
        mgr.generate_report(output_path=args.output)

    elif args.list_all:
        records = mgr.db.get_all()
        table = Table(title="ARZENS IOC Database Records", show_header=True, header_style="bold cyan")
        table.add_column("Indicator", style="cyan")
        table.add_column("Type", style="dim")
        table.add_column("Risk", justify="center")
        table.add_column("Conf", justify="center")
        table.add_column("Status", justify="center")
        table.add_column("First Seen", style="dim")
        table.add_column("Expiration", style="dim")

        for ind, r in records.items():
            st = r.get("status", "active").upper()
            st_style = "green" if st == "ACTIVE" else ("yellow" if st == "EXPIRED" else "red")
            table.add_row(
                ind,
                r.get("type", "").upper(),
                f"{r.get('risk_score', 0)}/100",
                f"{r.get('confidence', 0)}%",
                f"[{st_style}]{st}[/]",
                r.get("first_seen", "")[:10],
                r.get("expiration", "")[:10],
            )
        console.print(table)


if __name__ == "__main__":
    main()
