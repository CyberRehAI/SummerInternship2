import json
import csv
import hashlib
import math
import logging
import argparse
import os
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Iterator, Any
from collections import defaultdict, deque

import pandas as pd
import numpy as np

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class SecurityEvent:
    """
    Represents a normalized security event.
    """
    event_id: str
    timestamp: datetime
    event_type: str
    source_ip: str
    user_id: Optional[str]
    details: Dict[str, Any]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityEvent':
        """Creates a SecurityEvent from a dictionary."""
        return cls(
            event_id=data.get('event_id', ''),
            timestamp=datetime.strptime(data['timestamp'], "%Y-%m-%dT%H:%M:%SZ"),
            event_type=data.get('event_type', ''),
            source_ip=data.get('source_ip', ''),
            user_id=data.get('user_id'),
            details=data.get('details', {})
        )

@dataclass
class PrivacyConfig:
    """Configuration for privacy controls."""
    salt: str = "default_secure_salt_2026"
    ip_mask: int = 24
    laplace_sensitivity: float = 1.0
    laplace_epsilon: float = 0.5
    timestamp_resolution_minutes: int = 60

class PrivacyEngine:
    """Applies privacy-preserving transformations to security features."""
    
    def __init__(self, config: PrivacyConfig):
        self.config = config

    def pseudonymize(self, value: str) -> str:
        """Pseudonymize a string using SHA-256 and a salt."""
        if not value:
            return ""
        salted = f"{value}{self.config.salt}".encode('utf-8')
        return hashlib.sha256(salted).hexdigest()

    def generalize_ip(self, ip: str) -> str:
        """Generalize an IPv4 address by masking the last octet."""
        if not ip:
            return ""
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0"
        return ip

    def add_laplace_noise(self, value: float, sensitivity: Optional[float] = None, epsilon: Optional[float] = None) -> float:
        """Add Laplace noise to a numerical value for differential privacy."""
        s = sensitivity or self.config.laplace_sensitivity
        e = epsilon or self.config.laplace_epsilon
        if e <= 0:
            return value
        scale = s / e
        noise = np.random.laplace(0, scale)
        return float(value + noise)

    def round_timestamp(self, ts: datetime) -> datetime:
        """Round a timestamp to the configured resolution."""
        res_min = self.config.timestamp_resolution_minutes
        if res_min <= 0:
            return ts
        minutes = (ts.minute // res_min) * res_min
        return ts.replace(minute=minutes, second=0, microsecond=0)

class RollingWindowAggregator:
    """Aggregates events over a rolling window for feature extraction."""
    
    def __init__(self, window_size_seconds: int = 3600, step_size_seconds: int = 900):
        self.window_size = timedelta(seconds=window_size_seconds)
        self.step_size = timedelta(seconds=step_size_seconds)
        # We'll store events grouped by entity_id (user_id or source_ip)
        self.events_by_entity: Dict[str, deque] = defaultdict(deque)

    def add_event(self, entity_id: str, event: SecurityEvent):
        """Add an event to the aggregator."""
        if not entity_id:
            return
        self.events_by_entity[entity_id].append(event)
        
    def get_windows(self, entity_id: str, start_time: datetime, end_time: datetime) -> Iterator[Tuple[datetime, List[SecurityEvent]]]:
        """Yield windows of events for an entity."""
        events = self.events_by_entity.get(entity_id, deque())
        if not events:
            return

        current_start = start_time
        while current_start + self.window_size <= end_time:
            window_end = current_start + self.window_size
            window_events = [e for e in events if current_start <= e.timestamp < window_end]
            yield current_start, window_events
            current_start += self.step_size

    def evict_old_events(self, cutoff_time: datetime):
        """Evict events older than the cutoff_time from all deques."""
        for entity_id, events in self.events_by_entity.items():
            while events and events[0].timestamp < cutoff_time:
                events.popleft()

class SecurityFeatureExtractor:
    """Extracts security features from events."""
    
    @staticmethod
    def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Calculate the great circle distance in kilometers between two points."""
        R = 6371.0
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = math.sin(dlat / 2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Calculate the Shannon entropy of a string."""
        if not data:
            return 0.0
        prob = [float(data.count(c)) / len(data) for c in dict.fromkeys(list(data))]
        return -sum(p * math.log(p) / math.log(2.0) for p in prob)

    def _compute_failed_login_ratio(self, events: List[SecurityEvent]) -> float:
        """Ratio of failed logins to total logins."""
        logins = [e for e in events if e.event_type == 'auth' and e.details.get('action') == 'login']
        if not logins:
            return 0.0
        failures = sum(1 for e in logins if e.details.get('status') == 'failure')
        return failures / len(logins)

    def _compute_login_frequency(self, events: List[SecurityEvent], window_hours: float) -> float:
        """Number of logins per hour."""
        logins = [e for e in events if e.event_type == 'auth' and e.details.get('action') == 'login' and e.details.get('status') == 'success']
        if window_hours <= 0:
            return 0.0
        return len(logins) / window_hours

    def _compute_geo_velocity(self, events: List[SecurityEvent]) -> float:
        """Max geo-velocity in km/h between successive auth events."""
        auth_events = [e for e in events if e.event_type == 'auth' and 'geo_location' in e.details]
        auth_events.sort(key=lambda x: x.timestamp)
        max_vel = 0.0
        for i in range(1, len(auth_events)):
            e1, e2 = auth_events[i-1], auth_events[i]
            geo1, geo2 = e1.details['geo_location'], e2.details['geo_location']
            dist = self._haversine(geo1['lat'], geo1['lon'], geo2['lat'], geo2['lon'])
            time_diff_hours = (e2.timestamp - e1.timestamp).total_seconds() / 3600.0
            if time_diff_hours > 0:
                vel = dist / time_diff_hours
                max_vel = max(max_vel, vel)
        return max_vel

    def _compute_session_duration_anomaly(self, events: List[SecurityEvent]) -> float:
        """Z-score of session duration (simplified placeholder)."""
        # In a real scenario, this would track login/logout pairs.
        return 0.0

    def _compute_port_scan_index(self, events: List[SecurityEvent], window_seconds: float) -> float:
        """Rate of unique destination ports accessed per second."""
        net_events = [e for e in events if e.event_type == 'network']
        unique_ports = set(e.details.get('dest_port') for e in net_events if 'dest_port' in e.details)
        if window_seconds <= 0:
            return 0.0
        return len(unique_ports) / window_seconds

    def _compute_dns_query_entropy(self, events: List[SecurityEvent]) -> float:
        """Average Shannon entropy of DNS queries."""
        dns_events = [e for e in events if e.event_type == 'dns' and 'query' in e.details]
        if not dns_events:
            return 0.0
        entropies = [self._shannon_entropy(e.details['query']) for e in dns_events]
        return sum(entropies) / len(entropies)

    def _compute_data_exfil_ratio(self, events: List[SecurityEvent]) -> float:
        """Ratio of bytes sent to bytes received."""
        net_events = [e for e in events if e.event_type == 'network']
        bytes_sent = sum(e.details.get('bytes_sent', 0) for e in net_events)
        bytes_recv = sum(e.details.get('bytes_received', 0) for e in net_events)
        if bytes_recv == 0:
            return float(bytes_sent) if bytes_sent > 0 else 0.0
        return bytes_sent / bytes_recv

    def _compute_privilege_escalation_score(self, events: List[SecurityEvent]) -> float:
        """Score based on privilege escalation events."""
        score = 0.0
        for e in events:
            if e.event_type == 'endpoint' and e.details.get('privilege_change') == 'user_to_admin':
                score += 1.0
        return score

    def _compute_off_hours_ratio(self, events: List[SecurityEvent]) -> float:
        """Ratio of events occurring outside 9 AM - 5 PM."""
        if not events:
            return 0.0
        off_hours_count = 0
        for e in events:
            hour = e.timestamp.hour
            if hour < 9 or hour >= 17:
                off_hours_count += 1
        return off_hours_count / len(events)

    def _compute_connection_burstiness(self, events: List[SecurityEvent], sub_window: int = 300) -> float:
        """Variance of event counts in sub-windows (e.g. 5 minutes)."""
        if not events:
            return 0.0
        start_ts = min(e.timestamp for e in events)
        end_ts = max(e.timestamp for e in events)
        if (end_ts - start_ts).total_seconds() < sub_window:
            return 0.0
            
        bins = defaultdict(int)
        for e in events:
            bin_idx = int((e.timestamp - start_ts).total_seconds() // sub_window)
            bins[bin_idx] += 1
            
        counts = list(bins.values())
        if not counts:
            return 0.0
        return float(np.var(counts))

    def extract_features(self, entity_id: str, window_start: datetime, events: List[SecurityEvent], privacy: PrivacyEngine) -> Dict[str, Any]:
        """Extract all features for a given entity and window."""
        window_hours = 1.0
        window_seconds = 3600.0
        
        features = {
            'entity_id': privacy.pseudonymize(entity_id),
            'window_start': privacy.round_timestamp(window_start).isoformat(),
            'event_count': len(events),
            'failed_login_ratio': privacy.add_laplace_noise(self._compute_failed_login_ratio(events), 0.01, privacy.config.laplace_epsilon),
            'login_frequency': self._compute_login_frequency(events, window_hours),
            'geo_velocity': self._compute_geo_velocity(events),
            'session_duration_anomaly': self._compute_session_duration_anomaly(events),
            'port_scan_index': self._compute_port_scan_index(events, window_seconds),
            'dns_query_entropy': self._compute_dns_query_entropy(events),
            'data_exfil_ratio': self._compute_data_exfil_ratio(events),
            'privilege_escalation_score': self._compute_privilege_escalation_score(events),
            'off_hours_ratio': self._compute_off_hours_ratio(events),
            'connection_burstiness': self._compute_connection_burstiness(events, 300)
        }
        
        # Determine if entity is IP to generalize
        # Simplified: if it looks like an IP, generalize it in another field
        if "." in entity_id:
            features['generalized_ip'] = privacy.generalize_ip(entity_id)
        else:
            features['generalized_ip'] = None
            
        return features

class Exporter:
    """Handles exporting features to different formats."""
    
    @staticmethod
    def export_csv(features: List[Dict[str, Any]], filepath: str):
        """Export features to a CSV file."""
        if not features:
            logger.warning("No features to export to CSV.")
            return
        keys = features[0].keys()
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(features)
        logger.info(f"Exported {len(features)} records to {filepath}")

    @staticmethod
    def export_json(features: List[Dict[str, Any]], filepath: str):
        """Export features to a JSON file."""
        with open(filepath, 'w') as f:
            json.dump(features, f, indent=2)
        logger.info(f"Exported {len(features)} records to {filepath}")

    @staticmethod
    def generate_feature_dictionary(filepath: str):
        """Generate a markdown data dictionary for the features."""
        content = """# Feature Dictionary

| Feature Name | Description | Data Type | Privacy Applied |
|--------------|-------------|-----------|-----------------|
| `entity_id` | Pseudonymized identifier for the entity (User ID or Source IP). | String | SHA-256 Hashing |
| `window_start` | The start time of the aggregation window. | String (ISO) | Temporal Rounding |
| `event_count` | Total number of events in the window. | Integer | None |
| `failed_login_ratio` | Ratio of failed logins to total logins. | Float | Laplace Noise |
| `login_frequency` | Number of successful logins per hour. | Float | None |
| `geo_velocity` | Maximum geographical velocity between authentication events (km/h). | Float | None |
| `session_duration_anomaly` | Z-score anomaly for session duration. | Float | None |
| `port_scan_index` | Rate of unique destination ports accessed per second. | Float | None |
| `dns_query_entropy` | Average Shannon entropy of DNS queries. | Float | None |
| `data_exfil_ratio` | Ratio of bytes sent to bytes received. | Float | None |
| `privilege_escalation_score` | Count of privilege escalation occurrences. | Float | None |
| `off_hours_ratio` | Proportion of events occurring outside normal business hours (9AM-5PM). | Float | None |
| `connection_burstiness` | Variance of event counts in 5-minute sub-windows. | Float | None |
| `generalized_ip` | Generalized IP address if the entity is an IP. | String | Last Octet Masking |
"""
        with open(filepath, 'w') as f:
            f.write(content)
        logger.info(f"Generated feature dictionary at {filepath}")

def main():
    parser = argparse.ArgumentParser(description="Security Feature Extractor")
    parser.add_argument("--input", required=True, help="Path to input JSONL file")
    parser.add_argument("--output-dir", required=True, help="Path to output directory")
    args = parser.parse_args()

    input_file = args.input
    output_dir = args.output_dir

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    logger.info(f"Reading events from {input_file}")
    
    events = []
    with open(input_file, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    events.append(SecurityEvent.from_dict(json.loads(line)))
                except Exception as e:
                    logger.error(f"Error parsing event: {e}")

    if not events:
        logger.warning("No events found. Exiting.")
        return

    # Sort events by timestamp globally just in case
    events.sort(key=lambda e: e.timestamp)
    
    start_time = events[0].timestamp
    end_time = events[-1].timestamp
    
    logger.info(f"Loaded {len(events)} events from {start_time} to {end_time}")

    aggregator = RollingWindowAggregator()
    extractor = SecurityFeatureExtractor()
    privacy = PrivacyEngine(PrivacyConfig())

    # Add events to aggregator
    for e in events:
        # Group by user_id if present, else source_ip
        entity = e.user_id if e.user_id else e.source_ip
        aggregator.add_event(entity, e)

    all_features = []
    
    # Process windows for each entity
    for entity_id in aggregator.events_by_entity.keys():
        for w_start, w_events in aggregator.get_windows(entity_id, start_time, end_time):
            if w_events:
                features = extractor.extract_features(entity_id, w_start, w_events, privacy)
                all_features.append(features)

    # Export features
    csv_path = os.path.join(output_dir, "sample_features.csv")
    json_path = os.path.join(output_dir, "sample_features.json")
    dict_path = os.path.join(output_dir, "feature_dictionary.md")

    Exporter.export_csv(all_features, csv_path)
    Exporter.export_json(all_features, json_path)
    Exporter.generate_feature_dictionary(dict_path)

    logger.info("Extraction complete. Summary:")
    logger.info(f"Rows generated: {len(all_features)}")
    if all_features:
        logger.info(f"Columns per row: {len(all_features[0])}")
        logger.info(f"Sample row: {all_features[0]}")

if __name__ == "__main__":
    main()
