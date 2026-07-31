# Feature Dictionary

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
