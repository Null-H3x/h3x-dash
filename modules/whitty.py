#!/usr/bin/env python3
"""White Hat Penetration Testing Whitty 1-Liners - For code comments and documentation"""

whitty_one_liners = {
    "recon": [
        "Scanning the digital perimeter like a sentry ghost.",
        "Reconnaissance: finding weak spots before they find us.",
        "DNS enumeration — following the breadcrumbs to the hacker's cottage.",
        "Port scan in progress: knocking on every door, checking if it's unlocked.",
        "Banner grabbing: asking services 'who are you?'",
    ],
    
    "exploitation": [
        "Exploit loaded. Fingers crossed and fingers typed.",
        "Buffer overflow: pouring too much tea into a tiny cup.",
        "SQL injection: feeding the database a query it can't refuse.",
        "Remote code execution: sending digital commands to do our bidding.",
        "Privilege escalation: climbing the ladder from guest to king.",
    ],
    
    "post_exploitation": [
        "Pivoting through the network like a master thief in a heist.",
        "Credential dumping: collecting digital fingerprints for later use.",
        "Persistence established: leaving a backdoor where only we can find it.",
        "Clearing logs: erasing our digital footprints, leaving no trace.",
        "Exfiltration complete: data moving silently into the night.",
    ],
    
    "reporting": [
        "Finding vulnerabilities is easy. Fixing them? That's the real challenge.",
        "This report proves we're good guys with sharp tools.",
        "Exploitable vulnerability found. (And we didn't exploit it.)",
        "Risk assessment complete: we found the cracks, now you patch them.",
    ],
    
    "ethics": [
        "White hat: hammer in hand, consent in pocket.",
        "We break into systems to keep them safe — like fire drills for code.",
        "No data stolen. No systems damaged. Only vulnerabilities documented.",
        "Pen testing with a conscience and a signed SOW.",
    ],
    
    "general": [
        "Code is poetry, security is punctuation.",
        "Every line of code has a hidden flaw — we find them before attackers do.",
        "Security isn't a feature — it's the foundation.",
        "We don't hack to destroy. We hack to protect.",
    ]
}

def get_whitty(category="general"):
    """Get a random whitty one-liner from a category."""
    import random
    if category in whitty_one_liners:
        return random.choice(whitty_one_liners[category])
    return random.choice(whitty_one_liners["general"])

if __name__ == "__main__":
    print("=== White Hat Penetration Testing Whitty One-Liners ===\n")
    for cat, lines in whitty_one_liners.items():
        print(f"{cat.upper()}:")
        for line in lines:
            print(f"  • {line}")
        print()
