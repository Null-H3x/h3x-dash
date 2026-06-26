#!/usr/bin/env python3
"""Disruption (DoS) Engine for h3x-dash - Cyber Training Lab"""

tools = {
    "hping3": {"category": "Network", "desc": "TCP/UDP/ICMP packet generator"},
    "slowloris": {"category": "Web Exhaustion", "desc": "HTTP connection exhaustion"},
    "hydra": {"category": "Protocol Specific", "desc": "Brute force login attacks"},
    "nmap": {"category": "Network", "desc": "Port scanning/DoS scripts"},
    "masscan": {"category": "Network", "desc": "Fast port scanner"},
    "dnsperf": {"category": "Web Exhaustion", "desc": "DNS query flood"},
    "sqlmap": {"category": "Protocol Specific", "desc": "SQL injection stress testing"}
}

status = {
    "pending": "Waiting to launch",
    "running": "Attack in progress",
    "done": "Campaign completed",
    "error": "Tool failed"
}

def get_tools():
    return tools

def get_status_map():
    return status
