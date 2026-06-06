# Security Policy

## This Tool Is a Weapon. Treat It Like One.

H3x-Dash is an automated offensive security framework. It chains live
reconnaissance, exploitation, and post-exploitation tooling into a single
interface that fires real attacks at real systems. It is built for security
professionals operating under explicit, documented authorization, and for no
one else.

This is not a disclaimer drafted by a lawyer to cover someone. It is written by
an operator who has used these tools in the field and watched what happens when
people forget that "it worked in the lab" and "I was allowed to run it here" are
two completely different statements. Read this section as policy, not as
boilerplate. Using this tool means you accept every word of it.

---

## Authorized Use Only

**You may use H3x-Dash ONLY against:**

- Networks and systems you personally and provably own
- Networks and systems for which you hold a current, signed, written
  penetration testing agreement that explicitly covers the scope, the targets,
  and the timeframe in front of you
- Isolated lab environments (VMs, air-gapped ranges) you built specifically for
  security research and that touch no production network

**You may NOT use H3x-Dash against, under any circumstances:**

- Any network or system without explicit written authorization in hand before
  the first packet leaves your machine
- Cloud infrastructure (AWS, Azure, GCP, and every other provider) without the
  provider's explicit written approval. Their Terms of Service are binding, they
  log everything, and they will notice.
- Critical infrastructure of any kind. No exceptions, no "just a quick check",
  not ever.
- Systems belonging to an employer, client, or organization that has not
  contracted you in writing to test that exact target
- Anything you are unsure about. If you cannot produce the authorization
  document on demand, you do not have authorization.

Scope is not a suggestion. Authorization for one host is not authorization for
the host next to it. An agreement that expired yesterday is not an agreement.
"I had credentials" is not ownership, and "the door was open" has never once
worked as a legal defense.

Unauthorized use of this tool is a serious federal crime under the Computer
Fraud and Abuse Act (18 U.S.C. § 1030), the UK Computer Misuse Act, and
equivalent legislation in effectively every jurisdiction on Earth. Penalties
include felony convictions, substantial fines, and prison time. "I was just
testing" is not a defense. "I found a bug" is not permission. "I did not think
it would actually work" is not mitigation.

The author and contributors accept zero liability for damage, disruption, data
loss, legal action, or any other consequence arising from use of this tool.
The entire responsibility, legal, financial, ethical, and operational, rests
with the operator who runs it. If you point this at a target you were not
authorized to touch, that is on you and you alone.

---

## Operator Responsibilities

If you run H3x-Dash, you are accountable for the following, every time:

- Confirm scope and authorization in writing before launching anything
- Keep your testing inside the explicitly authorized target list
- Understand what each tool, scan tier, and exploit module actually does before
  you fire it. This framework will happily run a kernel exploit; it will not
  decide for you whether that is a good idea on a production box.
- Maintain logs of what you ran, when, and against what, for your own records
  and the client's
- Stop immediately and notify the appropriate party if you cause unintended
  disruption or discover you are outside scope

Automation removes keystrokes. It does not remove responsibility.

---

## Reporting Vulnerabilities in H3x-Dash

If you find a security vulnerability in H3x-Dash itself, for example a path
traversal in the report download endpoint, an SSRF via the scan target field,
or an authentication bypass, please report it responsibly.

**Do:**

- Open a GitHub Security Advisory (preferred)
- Or email the maintainer directly with `[H3x-Dash VULN]` in the subject line
- Give reasonable time for a fix before public disclosure (30 days is standard)

**Do not:**

- Open a public issue with exploit details
- Post a proof-of-concept before a patch is available

Responsible disclosure keeps everyone safer, including you.

---

## Lab Environment Recommendations

If you are building a practice range to test H3x-Dash against intentionally
vulnerable targets, the following are well-regarded options:

| Platform           | Focus                                |
|--------------------|--------------------------------------|
| Metasploitable 2/3 | Classic MSF target, all the classics |
| VulnHub            | Downloadable CTF-style VMs           |
| HackTheBox         | Guided lab with real CVEs            |
| DVWA               | Web app testing                      |
| PentestLab         | Mixed environment                    |
| TryHackMe          | Beginner-friendly guided rooms       |

Every platform above is built to be exploited. Your home network, your
employer's network, and the coffee shop Wi-Fi are not.

---

`H3x-Dash // Built for the people who know what they are doing.`
