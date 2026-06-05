# Security Policy

## This Tool Is a Weapon. Treat It Like One.

H3x-Dash is an automated penetration testing framework. It is built for
security professionals operating under explicit authorization. The following
is not a disclaimer written by a lawyer - it is written by someone who has
actually used these tools and understands the consequences of misuse.

---

## Authorized Use Only

**You may only use H3x-Dash against:**

- Networks and systems you personally own
- Networks and systems for which you hold a signed, written penetration
  testing agreement
- Isolated lab environments (VMs, air-gapped ranges) built specifically
  for security research

**You may not use H3x-Dash against:**

- Any network or system without explicit written authorization
- Cloud infrastructure (AWS, Azure, GCP) without the provider's explicit
  approval - yes, their ToS counts, and yes, they will notice
- Critical infrastructure of any kind, ever
- Systems belonging to organizations you work for but haven't been
  contracted to test

Unauthorized use of this tool is a federal crime under the Computer Fraud
and Abuse Act (18 U.S.C. § 1030), the UK Computer Misuse Act, and equivalent
legislation in virtually every jurisdiction on Earth. "I was just testing"
is not a defense. "I found a bug" is not permission.

---

## Reporting Vulnerabilities in H3x-Dash

If you find a security vulnerability in H3x-Dash itself - for example, a
path traversal in the report download endpoint, an SSRF via the scan target
field, or an authentication bypass - please report it responsibly.

**Do:**
- Open a GitHub Security Advisory (preferred)
- Or email the maintainer directly with `[H3x-Dash VULN]` in the subject line
- Give reasonable time for a fix before public disclosure (30 days is standard)

**Do not:**
- Open a public issue with exploit details
- Post a PoC before a patch is available

---

## Lab Environment Recommendations

If you're building a practice range to test H3x-Dash against intentionally
vulnerable targets, the following are well-regarded options:

| Platform         | Focus                          |
|-----------------|-------------------------------|
| Metasploitable 2/3 | Classic MSF target, all the classics |
| VulnHub          | Downloadable CTF-style VMs     |
| HackTheBox       | Guided lab with real CVEs      |
| DVWA             | Web app testing                |
| PentestLab       | Mixed environment              |
| TryHackMe        | Beginner-friendly guided rooms |

All of the above are designed to be exploited. Your home network is not.

---

`H3x-Dash // Built for the people who know what they're doing.`
