# Sentinel: Artifact Integrity Monitoring

**Sentinel** is a Windows file integrity and tamper-detection tool that alerts users when files or build artifacts have changed without authorization. By signing baselines with HMAC-SHA256 and maintaining a hash-chained audit log, Sentinel ensures that an attacker cannot alter or clear historical logs without detection. It integrates natively into CI/CD pipelines via a custom GitHub Action to safeguard critical software supply chain components.

---

## Key Features

* **File Integrity Monitoring:** Records file path, size, modification time, and SHA-256 hashes to detect modified, deleted, added, and moved files.
* **Anti-Tampering Controls:** Protects the trusted baseline using an HMAC-SHA256 signature and records scans in a sequential, hash-chained audit log.
* **Supply Chain Security:** Integrates with GitHub Actions to audit workflow definitions, Dockerfiles, and lockfiles, failing builds automatically on unexpected variations.
* **Web UI Dashboard:** Features a local web-based dashboard built with Vue and backed by Python to visually inspect configurations and run scans.
* **Flexible Alerting:** Generates results as console logs, JSON files, structured HTML reports, or real-time Slack and Discord webhook alerts.

---

## Commands

* **`INIT`** - Registers a target folder and builds the initial cryptographically signed baseline.
* **`VERIFY`** - Scans the folder structure against the baseline to discover tampered or updated items.
* **`ACCEPT`** - Approves legitimate file mutations and signs a new authoritative baseline.

---

## 📋 Scope Boundaries

* **In Scope:** Baseline checking, move detection, ignore rules, JSON/HTML reports, Discord/Slack webhooks, and CI/CD policy enforcement.
* **Stretch Goals:** Lockfile consistency verification, signed artifact manifests, and Windows toast alerts.
* **Out of Scope:** Real-time continuous file watching, ACL tracking, GitHub API commit checks, a built-in scheduler, and email notifications.

---


