# Threat Intelligence Platform — Setup Guide

## Prerequisites
- Ubuntu/Debian Linux
- Python 3.11+
- Docker & Docker Compose
- Root/sudo access (required for iptables enforcement)

---

## 1. Clone & install dependencies

```bash
cd tip_project
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 2. Configure environment

```bash
cp .env.example .env
nano .env   # Fill in your API keys and SMTP credentials
```

Required:
- `OTX_API_KEY` — free at https://otx.alienvault.com
- `VIRUSTOTAL_API_KEY` — free at https://www.virustotal.com

---

## 3. Start MongoDB + ELK Stack

```bash
docker-compose up -d
```

Wait ~60 seconds for Elasticsearch and Kibana to be ready.
- MongoDB:       http://localhost:27017
- Elasticsearch: http://localhost:9200
- Kibana:        http://localhost:5601

---

## 4. Import Kibana Dashboard

In Kibana UI:
1. Go to Stack Management → Saved Objects
2. Click Import
3. Upload `kibana/tip_dashboard.ndjson`
4. Go to Dashboards → "Threat Intelligence Platform — SOC Dashboard"

---

## 5. Run the platform (requires sudo for iptables)

```bash
sudo .venv/bin/python main.py
```

This starts:
- Ingestion scheduler (OTX, URLhaus, VirusTotal) — runs every hour
- SIEM sync to Elasticsearch — runs every 30 min
- Policy Enforcer daemon — polls MongoDB every 60s, auto-blocks high-risk IPs
- REST API on http://localhost:5000

---

## 6. REST API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/indicators | List all indicators (filter by type, blocked, min_score, source) |
| GET | /api/indicators/<value> | Get single indicator detail |
| GET | /api/logs | View enforcement action logs |
| GET | /api/stats | Summary stats (totals, by type, by source) |
| GET | /api/rules | Current iptables TIP_BLOCK chain rules |
| POST | /api/rollback | Rollback a false positive |

### Rollback example (false positive)
```bash
curl -X POST http://localhost:5000/api/rollback \
  -H "Content-Type: application/json" \
  -d '{"value": "1.2.3.4", "type": "ip", "rule_id": "abc12345", "analyst": "jsmith"}'
```

### Filter high-risk blocked IPs
```bash
curl "http://localhost:5000/api/indicators?type=ip&blocked=true&min_score=70"
```

---

## 7. Run individual components

```bash
# Ingestion only
python -m ingestion.otx_feed
python -m ingestion.urlhaus_feed
python -m ingestion.virustotal_feed

# SIEM sync only
python -m siem.elk_sync

# Enforcer only (requires sudo)
sudo .venv/bin/python -m enforcer.policy_enforcer
```

---

## 8. Safety — Rollback all TIP rules

In an emergency, flush ALL auto-blocked rules:

```bash
sudo .venv/bin/python -c "from enforcer.iptables_manager import flush_all_tip_rules; flush_all_tip_rules()"
```

Or manually:
```bash
sudo iptables -F TIP_BLOCK
```

---

## Project Structure

```
tip_project/
├── main.py                        # Main orchestrator
├── config.py                      # Central configuration
├── database.py                    # MongoDB helpers
├── requirements.txt
├── docker-compose.yml             # MongoDB + ELK stack
├── .env.example                   # Environment template
├── ingestion/
│   ├── otx_feed.py                # AlienVault OTX ingester
│   ├── urlhaus_feed.py            # URLhaus ingester (no key needed)
│   ├── virustotal_feed.py         # VirusTotal enrichment
│   └── normalizer.py              # Validation + risk scoring
├── siem/
│   └── elk_sync.py                # Elasticsearch sync
├── enforcer/
│   ├── iptables_manager.py        # iptables / /etc/hosts rules
│   └── policy_enforcer.py        # Enforcement daemon + rollback
├── alerting/
│   └── notifier.py                # Email alerts (SMTP)
├── api/
│   └── app.py                     # Flask REST API
└── kibana/
    └── tip_dashboard.ndjson       # Kibana dashboard export
```
"# Finance-Banking" 
