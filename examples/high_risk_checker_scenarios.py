"""
High-Risk IP Checker - Example Usage Scenarios
Demonstrates practical ways to use the high-risk IP checker in your SOC workflow.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.high_risk_checker import HighRiskChecker
from datetime import datetime
from loguru import logger


def scenario_1_daily_threat_report():
    """
    SCENARIO 1: Generate a daily threat report for the SOC manager
    Use case: Email report sent every morning with high-risk IP summary
    """
    print("\n" + "="*70)
    print("SCENARIO 1: Daily Threat Report")
    print("="*70)
    
    checker = HighRiskChecker()
    stats = checker.get_statistics()
    
    report = f"""
DAILY THREAT INTELLIGENCE REPORT
Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

SUMMARY
-------
Total High-Risk IPs: {stats['total_high_risk']}
  ├─ Blocked: {stats['blocked']}
  ├─ Unblocked (ACTION REQUIRED): {stats['unblocked']}
  └─ Threshold: {stats['threshold']}

THREATS BY SOURCE
-----------------
"""
    for source, count in sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True):
        report += f"  {source}: {count}\n"
    
    report += "\nTOP THREAT TAGS\n" + "-"*40 + "\n"
    for tag, count in sorted(stats['top_tags'].items(), key=lambda x: x[1], reverse=True)[:10]:
        report += f"  {tag}: {count}\n"
    
    # Get critical IPs
    critical = checker.get_critical_ips()
    report += f"\nCRITICAL IPs (Score >= 90, Unblocked): {len(critical)}\n" + "-"*40 + "\n"
    if critical:
        for ip in critical[:10]:
            tags_str = ", ".join(ip.get('tags', [])[:3])
            report += f"  • {ip['value']:20} Risk: {ip['risk_score']:3}  Tags: {tags_str}\n"
        if len(critical) > 10:
            report += f"  ... and {len(critical) - 10} more\n"
    
    print(report)
    return report


def scenario_2_incident_response():
    """
    SCENARIO 2: Incident response context gathering
    Use case: Security analyst investigates a potential compromise
    """
    print("\n" + "="*70)
    print("SCENARIO 2: Incident Response - Quick Context")
    print("="*70)
    
    checker = HighRiskChecker()
    
    # Simulate: analyst finds suspicious IP in logs
    suspect_ip = "192.0.2.1"  # Example IP
    
    print(f"\nInvestigating IP: {suspect_ip}\n" + "-"*40)
    
    result = checker.check_ip(suspect_ip)
    
    if result:
        print(f"✓ IP found in threat database")
        print(f"  Risk Score: {result.get('risk_score', 'N/A')}")
        print(f"  High Risk: {'YES ⚠️' if result.get('is_high_risk') else 'NO'}")
        print(f"  Blocked: {'YES' if result.get('blocked') else 'NO - RECOMMEND BLOCKING'}")
        print(f"  Source: {result.get('source', 'Unknown')}")
        print(f"  Tags: {', '.join(result.get('tags', []))}")
        print(f"  Seen {result.get('seen_count', 1)} times")
        print(f"  First Seen: {result.get('first_seen', 'N/A')}")
        print(f"  Last Seen: {result.get('last_seen', 'N/A')}")
    else:
        print(f"✗ IP not found in threat database (likely clean)")


def scenario_3_threat_hunting():
    """
    SCENARIO 3: Active threat hunting
    Use case: Hunt for specific threat patterns
    """
    print("\n" + "="*70)
    print("SCENARIO 3: Threat Hunting - Active Investigation")
    print("="*70)
    
    checker = HighRiskChecker()
    
    # Hunt 1: Find recent malware
    print("\n[Hunt 1] Recent malware-hosting infrastructure (last 24 hours)")
    print("-" * 60)
    recent_malware = checker.get_recent_high_risk(hours=24)
    recent_malware = [ip for ip in recent_malware if 'malware' in [t.lower() for t in ip.get('tags', [])]]
    
    print(f"Found: {len(recent_malware)} recent malware IPs")
    if recent_malware:
        for ip in recent_malware[:5]:
            print(f"  • {ip['value']:20} Risk: {ip['risk_score']}  Source: {ip['source']}")
        if len(recent_malware) > 5:
            print(f"  ... and {len(recent_malware) - 5} more")
    
    # Hunt 2: Find botnet infrastructure
    print("\n[Hunt 2] Botnet command & control servers")
    print("-" * 60)
    botnet_ips = checker.get_high_risk_by_tag('botnet')
    print(f"Found: {len(botnet_ips)} botnet IPs")
    
    if botnet_ips:
        by_source = {}
        for ip in botnet_ips:
            source = ip.get('source', 'Unknown')
            if source not in by_source:
                by_source[source] = []
            by_source[source].append(ip)
        
        for source, ips in by_source.items():
            print(f"  From {source}: {len(ips)} IPs")
    
    # Hunt 3: Compare threat intelligence sources
    print("\n[Hunt 3] Threat intelligence source comparison")
    print("-" * 60)
    stats = checker.get_statistics()
    for source, count in sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {source}: {count} high-risk indicators")


def scenario_4_automated_blocking():
    """
    SCENARIO 4: Automated blocking workflow
    Use case: Automatically block critical threats without manual review
    """
    print("\n" + "="*70)
    print("SCENARIO 4: Automated Blocking (Simulation)")
    print("="*70)
    
    checker = HighRiskChecker()
    
    # Get critical unblocked IPs
    critical = checker.get_critical_ips()
    
    print(f"\nCritical unblocked IPs: {len(critical)}")
    print("Simulating automated block action...\n")
    
    blocked_count = 0
    for ip in critical[:5]:  # Process top 5
        print(f"  → Blocking {ip['value']}")
        print(f"    Reason: {', '.join(ip.get('tags', [])[:2])}")
        print(f"    Risk Score: {ip['risk_score']}")
        blocked_count += 1
        # In real scenario, would call: enforce_block(ip['value'], rule_id, reason)
    
    if len(critical) > 5:
        print(f"\n  ... would block {len(critical) - 5} more in batch")
    
    print(f"\nTotal blocks executed: {min(blocked_count, len(critical))}")


def scenario_5_siem_integration():
    """
    SCENARIO 5: Integrate with SIEM/Monitoring system
    Use case: Query high-risk IPs for correlation with security events
    """
    print("\n" + "="*70)
    print("SCENARIO 5: SIEM Integration")
    print("="*70)
    
    checker = HighRiskChecker()
    
    # Simulate SIEM query for high-risk activity
    print("\n[SIEM Query] Correlating logs with high-risk IPs\n" + "-"*60)
    
    # Get IPs for last 24 hours
    recent = checker.get_recent_high_risk(hours=24)
    
    print(f"High-risk IPs from last 24 hours: {len(recent)}")
    print("\nSimulated SIEM correlation:")
    
    if recent:
        # Show potential false positives
        print("\n⚠️  IPs to investigate:")
        for ip in recent[:3]:
            print(f"  • {ip['value']}")
            print(f"    Risk: {ip['risk_score']} | Source: {ip['source']}")
            print(f"    Tags: {', '.join(ip.get('tags', [])[:3])}")
            print(f"    → Check if matching security events in SIEM")
    
    # Integration suggestion
    print("\n[Integration Suggestion]")
    print("  1. Fetch high-risk IPs from /api/high-risk-ips every 5 minutes")
    print("  2. Cross-reference with SIEM event sources")
    print("  3. Alert on correlation matches")
    print("  4. Adjust correlation threshold based on risk score")


def scenario_6_compliance_report():
    """
    SCENARIO 6: Compliance and audit reporting
    Use case: Generate report for security compliance review
    """
    print("\n" + "="*70)
    print("SCENARIO 6: Compliance & Audit Report")
    print("="*70)
    
    checker = HighRiskChecker()
    
    stats = checker.get_statistics()
    all_high_risk = checker.get_high_risk_ips()
    blocked = checker.get_high_risk_ips(blocked_only=True)
    
    report = f"""
SECURITY COMPLIANCE AUDIT REPORT
Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

COMPLIANCE METRICS
------------------
Total High-Risk Indicators: {stats['total_high_risk']}
Successfully Blocked: {stats['blocked']} ({100*stats['blocked']/max(1, stats['total_high_risk']):.1f}%)
Pending Action: {stats['unblocked']} ({100*stats['unblocked']/max(1, stats['total_high_risk']):.1f}%)

THREAT LANDSCAPE
----------------
Risk Threshold: {stats['threshold']}
Indicators by Type:
  {chr(10).join(f"  • {k}: {v}" for k, v in stats['by_source'].items())}

RESPONSE TIME ANALYSIS
----------------------
For compliance, verify:
  ✓ All critical IPs (score >= 90) blocked within 24 hours
  ✓ High-risk IPs (score >= 70) blocked within 48 hours
  ✓ Manual review completed for false positives
  ✓ Rollback logs maintained for audit trail

ACTION ITEMS
------------
Pending blocks: {stats['unblocked']} IPs
Estimated resolution: Review and block per severity
Current SLA compliance: PENDING REVIEW

"""
    print(report)
    return report


def scenario_7_api_monitoring():
    """
    SCENARIO 7: Continuous monitoring via REST API
    Use case: Monitor system health and alert on anomalies
    """
    print("\n" + "="*70)
    print("SCENARIO 7: API Monitoring Setup")
    print("="*70)
    
    print("""
RECOMMENDED API POLLING STRATEGY
---------------------------------

Every 15 minutes (health check):
  GET /api/high-risk-stats
  Alert if: unblocked IPs > threshold

Every hour (detailed review):
  GET /api/high-risk-ips?filter=unblocked&limit=100
  Alert if: critical_count > 5

Daily (management report):
  GET /api/high-risk-ips?type=all&limit=500
  Generate trends and patterns

ALERT CONDITIONS
----------------
Critical: 5+ unblocked IPs with score >= 90
High:     20+ unblocked IPs with score >= 80
Medium:   50+ unblocked IPs with score >= 70

CURL EXAMPLES for Monitoring
-----------------------------
""")
    
    curl_examples = """
# Health check (should be fast)
curl -s "http://localhost:5000/api/high-risk-stats" | jq '.unblocked'

# Get critical IPs
curl -s "http://localhost:5000/api/high-risk-ips?filter=critical&limit=50" | jq '.count'

# Recent threat activity
curl -s "http://localhost:5000/api/high-risk-ips?recent_hours=24&limit=100" | jq '.ips | length'

# Source breakdown
curl -s "http://localhost:5000/api/high-risk-stats" | jq '.by_source'
    """
    print(curl_examples)


def main():
    """Run all scenarios"""
    print("\n" + "█"*70)
    print("█" + " "*68 + "█")
    print("█" + "  HIGH-RISK IP CHECKER - PRACTICAL USAGE SCENARIOS".center(68) + "█")
    print("█" + " "*68 + "█")
    print("█"*70)
    
    try:
        scenario_1_daily_threat_report()
        scenario_2_incident_response()
        scenario_3_threat_hunting()
        scenario_4_automated_blocking()
        scenario_5_siem_integration()
        scenario_6_compliance_report()
        scenario_7_api_monitoring()
        
        print("\n" + "="*70)
        print("All scenarios completed!")
        print("="*70)
        print("\nFor more details, see: HIGH_RISK_IP_GUIDE.md")
        print("For quick commands, see: HIGH_RISK_IP_QUICK_REFERENCE.md\n")
        
    except Exception as e:
        logger.error(f"Error running scenarios: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
