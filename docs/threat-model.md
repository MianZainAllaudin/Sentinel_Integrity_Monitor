# Threat Model

Sentinel protects against undetected modification of monitored files by an attacker who does not control the Sentinel state directory or HMAC key.

Protected by:
- HMAC-SHA256 signature on the baseline (key not stored with baseline).
- Hash-chained audit log detecting edits/removal of audit entries.

Limitations:
- An attacker who controls the user account and can read `SENTINEL_HMAC_KEY` can forge baselines and rewrite the audit chain.
- A local hash chain does not protect against full log replacement or tail truncation without a separately protected checkpoint.

Out of scope: real-time monitoring, ACL tracking, email alerts.
