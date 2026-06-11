"""
High-Risk IP Checker Utility
Provides multiple interfaces for querying and analyzing high-risk IPs in the system.
"""
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from tabulate import tabulate

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database import get_indicators_collection
from loguru import logger
import config


class HighRiskChecker:
    """Query and analyze high-risk IPs in the threat intelligence database."""
    
    def __init__(self, risk_threshold: Optional[int] = None):
        """
        Initialize the checker.
        
        Args:
            risk_threshold: Risk score threshold (default: RISK_SCORE_HIGH from config)
        """
        self.risk_threshold = risk_threshold or config.RISK_SCORE_HIGH
        self.col = get_indicators_collection()
    
    def get_high_risk_ips(self, blocked_only: bool = False, unblocked_only: bool = False) -> List[Dict]:
        """
        Retrieve high-risk IPs from the database.
        
        Args:
            blocked_only: Only return already-blocked IPs
            unblocked_only: Only return unblocked IPs (recommended for action)
            
        Returns:
            List of IP indicator documents sorted by risk score (descending)
        """
        query = {
            "type": "ip",
            "risk_score": {"$gte": self.risk_threshold}
        }
        
        if blocked_only:
            query["blocked"] = True
        elif unblocked_only:
            query["blocked"] = False
        
        results = list(
            self.col.find(query, {"_id": 0})
            .sort("risk_score", -1)
        )
        return results
    
    def get_critical_ips(self) -> List[Dict]:
        """Get only the most critical IPs (score >= 90)."""
        query = {
            "type": "ip",
            "risk_score": {"$gte": 90},
            "blocked": False
        }
        return list(
            self.col.find(query, {"_id": 0})
            .sort("risk_score", -1)
        )
    
    def get_high_risk_by_source(self, source: str) -> List[Dict]:
        """Get high-risk IPs from a specific source."""
        query = {
            "type": "ip",
            "risk_score": {"$gte": self.risk_threshold},
            "source": source,
            "blocked": False
        }
        return list(
            self.col.find(query, {"_id": 0})
            .sort("risk_score", -1)
        )
    
    def get_recent_high_risk(self, hours: int = 24) -> List[Dict]:
        """Get high-risk IPs discovered in the last N hours."""
        since = datetime.utcnow() - timedelta(hours=hours)
        query = {
            "type": "ip",
            "risk_score": {"$gte": self.risk_threshold},
            "blocked": False,
            "first_seen": {"$gte": since}
        }
        return list(
            self.col.find(query, {"_id": 0})
            .sort("risk_score", -1)
        )
    
    def get_high_risk_by_tag(self, tag: str) -> List[Dict]:
        """Get high-risk IPs with a specific tag (e.g., 'malware', 'botnet')."""
        query = {
            "type": "ip",
            "risk_score": {"$gte": self.risk_threshold},
            "blocked": False,
            "tags": tag.lower()
        }
        return list(
            self.col.find(query, {"_id": 0})
            .sort("risk_score", -1)
        )
    
    def get_statistics(self) -> Dict:
        """Get summary statistics about high-risk IPs."""
        query = {"type": "ip", "risk_score": {"$gte": self.risk_threshold}}
        
        stats = {
            "total_high_risk": self.col.count_documents(query),
            "blocked": self.col.count_documents({**query, "blocked": True}),
            "unblocked": self.col.count_documents({**query, "blocked": False}),
            "threshold": self.risk_threshold,
        }
        
        # By source breakdown
        pipeline = [
            {"$match": query},
            {"$group": {"_id": "$source", "count": {"$sum": 1}}}
        ]
        stats["by_source"] = {d["_id"]: d["count"] for d in self.col.aggregate(pipeline)}
        
        # By tag breakdown (top 10)
        pipeline = [
            {"$match": query},
            {"$unwind": "$tags"},
            {"$group": {"_id": "$tags", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        stats["top_tags"] = {d["_id"]: d["count"] for d in self.col.aggregate(pipeline)}
        
        return stats
    
    def check_ip(self, ip: str) -> Optional[Dict]:
        """Get detailed information about a specific IP."""
        doc = self.col.find_one({"type": "ip", "value": ip}, {"_id": 0})
        if doc:
            doc["is_high_risk"] = doc.get("risk_score", 0) >= self.risk_threshold
        return doc
    
    def format_table(self, ips: List[Dict], max_rows: int = 50) -> str:
        """Format IP list as a pretty table."""
        if not ips:
            return "No high-risk IPs found."
        
        rows = []
        for ip in ips[:max_rows]:
            tags = ", ".join(ip.get("tags", [])[:3])  # Show first 3 tags
            if len(ip.get("tags", [])) > 3:
                tags += f" +{len(ip['tags']) - 3}"
            
            blocked_status = "✓" if ip.get("blocked") else "✗"
            
            rows.append([
                ip.get("value"),
                ip.get("risk_score", 0),
                ip.get("source", "Unknown"),
                tags,
                blocked_status,
                ip.get("seen_count", 1),
            ])
        
        return tabulate(
            rows,
            headers=["IP Address", "Risk Score", "Source", "Tags", "Blocked", "Seen Count"],
            tablefmt="grid"
        )


def main():
    """CLI interface for high-risk IP checking."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Check for high-risk IPs in the Threat Intelligence Platform"
    )
    parser.add_argument(
        "--type",
        choices=["all", "unblocked", "blocked", "critical"],
        default="unblocked",
        help="Filter type (default: unblocked)"
    )
    parser.add_argument(
        "--source",
        help="Filter by source (e.g., 'OTX', 'VirusTotal')"
    )
    parser.add_argument(
        "--tag",
        help="Filter by tag (e.g., 'malware', 'botnet')"
    )
    parser.add_argument(
        "--recent",
        type=int,
        metavar="HOURS",
        help="Show IPs discovered in the last N hours"
    )
    parser.add_argument(
        "--check",
        metavar="IP",
        help="Check details for a specific IP"
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Show summary statistics"
    )
    parser.add_argument(
        "--threshold",
        type=int,
        help="Custom risk score threshold (default: 70)"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Limit number of results (default: 50)"
    )
    
    args = parser.parse_args()
    
    checker = HighRiskChecker(risk_threshold=args.threshold)
    
    # Show statistics if requested
    if args.stats:
        stats = checker.get_statistics()
        print("\n=== High-Risk IP Statistics ===")
        print(f"Total high-risk IPs: {stats['total_high_risk']}")
        print(f"  - Blocked: {stats['blocked']}")
        print(f"  - Unblocked: {stats['unblocked']}")
        print(f"  - Threshold: {stats['threshold']}")
        print("\nBy Source:")
        for source, count in sorted(stats["by_source"].items(), key=lambda x: x[1], reverse=True):
            print(f"  {source}: {count}")
        print("\nTop Tags:")
        for tag, count in sorted(stats["top_tags"].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {tag}: {count}")
        print()
        return
    
    # Check specific IP
    if args.check:
        result = checker.check_ip(args.check)
        if result:
            print(f"\n=== IP: {args.check} ===")
            print(f"Risk Score: {result.get('risk_score', 0)}")
            print(f"Is High Risk: {result.get('is_high_risk', False)}")
            print(f"Blocked: {result.get('blocked', False)}")
            print(f"Source: {result.get('source', 'Unknown')}")
            print(f"Tags: {', '.join(result.get('tags', []))}")
            print(f"Seen Count: {result.get('seen_count', 1)}")
            print(f"First Seen: {result.get('first_seen', 'Unknown')}")
            print(f"Last Seen: {result.get('last_seen', 'Unknown')}")
        else:
            print(f"IP {args.check} not found in database.")
        return
    
    # Get IPs based on filters
    if args.tag:
        ips = checker.get_high_risk_by_tag(args.tag)
        print(f"\n=== High-Risk IPs with tag '{args.tag}' ===")
    elif args.source:
        ips = checker.get_high_risk_by_source(args.source)
        print(f"\n=== High-Risk IPs from source '{args.source}' ===")
    elif args.recent:
        ips = checker.get_recent_high_risk(hours=args.recent)
        print(f"\n=== High-Risk IPs discovered in last {args.recent} hours ===")
    elif args.type == "critical":
        ips = checker.get_critical_ips()
        print(f"\n=== CRITICAL IPs (Risk >= 90) ===")
    elif args.type == "blocked":
        ips = checker.get_high_risk_ips(blocked_only=True)
        print(f"\n=== Blocked High-Risk IPs ===")
    elif args.type == "all":
        ips = checker.get_high_risk_ips()
        print(f"\n=== All High-Risk IPs ===")
    else:  # unblocked (default)
        ips = checker.get_high_risk_ips(unblocked_only=True)
        print(f"\n=== Unblocked High-Risk IPs (Action Required) ===")
    
    print(f"Found {len(ips)} results\n")
    print(checker.format_table(ips, max_rows=args.limit))
    print()


if __name__ == "__main__":
    main()
