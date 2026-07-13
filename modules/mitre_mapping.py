"""
mitre_mapping.py — CVE → MITRE ATT&CK techniques and CVSS v3.1 lookups.

Reporting tags each finding with:
  - attack_techniques:  list of ATT&CK technique IDs (T1190 etc.)
  - cvss_score:         float, 0.0–10.0
  - cvss_vector:        CVSS v3.1 vector string (empty if not in NVD map)

Mappings are sourced from:
  - MITRE ATT&CK Enterprise matrix (https://attack.mitre.org)
  - NVD CVSS v3.1 vectors (https://nvd.nist.gov)

Coverage is intentionally focused on the CveChain entries — adding a CVE
to the chain WITHOUT a CVSS map entry is fine; the severity-based estimate
takes over. Adding a CVSS map entry without a chain entry is also fine.

Public API:
  attack_techniques_for(msf_module, finding_type)  -> list[str]
  cvss_for(cve, severity)                           -> (score, vector)
  annotate_finding(finding)                         -> dict (copy, augmented)
  attack_matrix(findings)                           -> dict[technique, [finding]]
  technique_label(technique_id)                     -> str
"""

from __future__ import annotations


# ── ATT&CK technique reference (subset that maps to chain modules) ────────────
# Format: technique_id → human-readable label
# Reference: https://attack.mitre.org/techniques/enterprise/

ATTACK_TECHNIQUES = {
    'T1003':       'OS Credential Dumping',
    'T1003.001':   'LSASS Memory',
    'T1003.006':   'DCSync',
    'T1018':       'Remote System Discovery',
    'T1021.001':   'Remote Services: RDP',
    'T1021.002':   'Remote Services: SMB / Admin Shares',
    'T1021.004':   'Remote Services: SSH',
    'T1021.006':   'Remote Services: WinRM',
    'T1059':       'Command and Scripting Interpreter',
    'T1059.001':   'PowerShell',
    'T1068':       'Exploitation for Privilege Escalation',
    'T1078':       'Valid Accounts',
    'T1078.002':   'Domain Accounts',
    'T1083':       'File and Directory Discovery',
    'T1087':       'Account Discovery',
    'T1087.001':   'Local Accounts',
    'T1087.002':   'Domain Accounts',
    'T1090':       'Proxy / Relay',
    'T1098':       'Account Manipulation',
    'T1110':       'Brute Force',
    'T1110.001':   'Password Guessing',
    'T1110.003':   'Password Spraying',
    'T1110.004':   'Credential Stuffing',
    'T1133':       'External Remote Services',
    'T1135':       'Network Share Discovery',
    'T1190':       'Exploit Public-Facing Application',
    'T1210':       'Exploitation of Remote Services',
    'T1212':       'Exploitation for Credential Access',
    'T1499':       'Endpoint Denial of Service',
    'T1505.003':   'Web Shell',
    'T1552.001':   'Credentials In Files',
    'T1557.001':   'LLMNR/NBT-NS Poisoning + SMB Relay',
    'T1558.003':   'Kerberoasting',
    'T1573.001':   'Symmetric Cryptography (weak)',
    'T1592':       'Gather Victim Host Information',
    'T1595':       'Active Scanning',
    'T1595.002':   'Vulnerability Scanning',
}


# ── MSF module → ATT&CK techniques ────────────────────────────────────────────
# Module paths match cve_chain.py exactly (validated by validate_chain.py).

MODULE_ATTACK_MAP: dict[str, list[str]] = {
    # SMB / Samba
    'exploit/windows/smb/ms17_010_eternalblue':                ['T1210', 'T1078'],
    'exploit/windows/smb/ms17_010_psexec':                     ['T1021.002', 'T1078'],
    'exploit/windows/smb/cve_2020_0796_smbghost':              ['T1210'],
    'exploit/linux/samba/is_known_pipename':                   ['T1210'],
    'exploit/multi/samba/usermap_script':                      ['T1210'],
    'auxiliary/scanner/smb/smb_ms17_010':                      ['T1595.002'],
    'auxiliary/scanner/smb/smb_login':                         ['T1110.001'],
    'auxiliary/scanner/smb/smb_enumshares':                    ['T1135'],
    'auxiliary/scanner/smb/smb_enumusers':                     ['T1087.002'],
    'auxiliary/scanner/smb/smb_version':                       ['T1592'],
    # DCERPC / Windows core
    'auxiliary/admin/dcerpc/cve_2020_1472_zerologon':          ['T1003.006', 'T1098'],
    'exploit/windows/dcerpc/cve_2021_1675_printnightmare':     ['T1068', 'T1210'],
    'exploit/windows/dcerpc/ms03_026_dcom':                    ['T1210'],
    # WinRM
    'exploit/windows/winrm/winrm_script_exec':                 ['T1021.006'],
    'auxiliary/scanner/winrm/winrm_login':                     ['T1110.001'],
    'auxiliary/scanner/winrm/winrm_auth_methods':              ['T1595.002'],
    # RDP
    'exploit/windows/rdp/cve_2019_0708_bluekeep_rce':          ['T1210'],
    'auxiliary/dos/windows/rdp/ms12_020_maxchannelids':        ['T1499'],
    # FTP
    'exploit/unix/ftp/vsftpd_234_backdoor':                    ['T1210'],
    'exploit/freebsd/ftp/proftp_telnet_iac':                   ['T1210'],
    'auxiliary/scanner/ftp/ftp_login':                         ['T1110.001'],
    'auxiliary/scanner/ftp/anonymous':                         ['T1078'],
    # SSH
    'auxiliary/scanner/ssh/ssh_login':                         ['T1110.001'],
    'auxiliary/scanner/ssh/ssh_enumusers':                     ['T1087'],
    # HTTP family
    'exploit/multi/http/apache_normalize_path_rce':            ['T1190'],
    'exploit/multi/http/apache_mod_cgi_bash_env_exec':         ['T1190'],
    'exploit/multi/http/log4shell_header_injection':           ['T1190'],
    'auxiliary/scanner/http/log4shell_scanner':                ['T1595.002'],
    'exploit/multi/http/struts2_content_type_ognl':            ['T1190'],
    'exploit/multi/http/spring_framework_rce_spring4shell':    ['T1190'],
    'exploit/multi/http/atlassian_confluence_webwork_ognl_injection': ['T1190'],
    'exploit/multi/http/php_fpm_rce':                          ['T1190'],
    'exploit/multi/http/tomcat_mgr_upload':                    ['T1505.003', 'T1078'],
    'exploit/multi/http/tomcat_jsp_upload_bypass':             ['T1505.003'],
    'exploit/multi/http/gitlab_exif_rce':                      ['T1190'],
    'exploit/multi/http/jenkins_script_console':               ['T1059.001'],
    'exploit/unix/webapp/drupal_drupalgeddon2':                ['T1190'],
    'exploit/multi/http/jboss_invoke_deploy':                  ['T1505.003'],
    'exploit/windows/iis/iis_webdav_upload_asp':               ['T1505.003'],
    'auxiliary/scanner/http/wordpress_login_enum':             ['T1087', 'T1110.001'],
    'auxiliary/scanner/http/dir_listing':                      ['T1083'],
    'auxiliary/scanner/http/options':                          ['T1595.002'],
    # AJP / RMI / IRC / distcc
    'auxiliary/admin/http/tomcat_ghostcat':                    ['T1083', 'T1190'],
    'exploit/multi/misc/java_rmi_server':                      ['T1210'],
    'exploit/unix/irc/unreal_ircd_3281_backdoor':              ['T1210'],
    'exploit/unix/misc/distcc_exec':                           ['T1210'],
    # DBs
    'auxiliary/scanner/mssql/mssql_login':                     ['T1110.001'],
    'exploit/windows/mssql/mssql_payload':                     ['T1059'],
    'auxiliary/scanner/mssql/mssql_hashdump':                  ['T1003'],
    'auxiliary/scanner/mysql/mysql_authbypass_hashdump':       ['T1003'],
    'auxiliary/scanner/mysql/mysql_login':                     ['T1110.001'],
    'auxiliary/scanner/mysql/mysql_hashdump':                  ['T1003'],
    'auxiliary/scanner/postgres/postgres_login':               ['T1110.001'],
    'auxiliary/scanner/postgres/postgres_hashdump':            ['T1003'],
    'exploit/linux/redis/redis_replication_cmd_exec':          ['T1190', 'T1210'],
    # VNC
    'auxiliary/scanner/vnc/vnc_none_auth':                     ['T1078'],
    'auxiliary/scanner/vnc/vnc_login':                         ['T1110.001'],
    # LDAP / SNMP / DNS / Mail
    'auxiliary/scanner/ldap/ldap_login':                       ['T1110.001'],
    'auxiliary/gather/ldap_query':                             ['T1087.002'],
    'auxiliary/scanner/snmp/snmp_enum':                        ['T1592'],
    'auxiliary/scanner/snmp/snmp_login':                       ['T1110.001'],
    'auxiliary/gather/enum_dns':                               ['T1018', 'T1592'],
    'auxiliary/scanner/smtp/smtp_enum':                        ['T1087'],
    'auxiliary/scanner/smtp/smtp_relay':                       ['T1090'],
    'auxiliary/scanner/pop3/pop3_login':                       ['T1110.001'],
    'auxiliary/scanner/imap/imap_version':                     ['T1592'],
    'auxiliary/scanner/telnet/telnet_login':                   ['T1110.001'],
}


# ── CVE → CVSS v3.1 (score, vector) ───────────────────────────────────────────
# NVD-sourced for the chain's CVEs. Vector blank means score-only.

CVE_CVSS_MAP: dict[str, tuple[float, str]] = {
    # SMB / Samba
    'CVE-2017-0144': (8.1,  'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2017-0145': (8.1,  'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2020-0796': (10.0, 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'),
    'CVE-2017-7494': (9.8,  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2007-2447': (9.8,  ''),
    # Windows core
    'CVE-2020-1472': (10.0, 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'),
    'CVE-2021-1675': (8.8,  'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2021-34527':(8.8,  'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2003-0352': (7.5,  ''),
    # RDP
    'CVE-2019-0708': (9.8,  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2019-1182': (9.8,  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2012-0002': (7.8,  ''),
    # FTP
    'CVE-2011-2523': (10.0, ''),
    'CVE-2010-4221': (7.5,  ''),
    # SSH
    'CVE-2023-38408':(9.8,  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2018-15473':(5.3,  'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
    'CVE-2016-6515': (7.5,  ''),
    # Web
    'CVE-2021-41773':(7.5,  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
    'CVE-2021-42013':(9.8,  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2017-5638': (10.0, 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'),
    'CVE-2019-11043':(9.8,  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2014-6271': (9.8,  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2022-22965':(9.8,  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2021-44228':(10.0, 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'),
    'CVE-2022-26134':(9.8,  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2021-22205':(10.0, 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'),
    'CVE-2018-7600': (9.8,  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2020-1938': (9.8,  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    # IRC / distcc / Java RMI
    'CVE-2010-2075': (10.0, ''),
    'CVE-2004-2687': (9.3,  ''),
    # DBs
    'CVE-2012-2122': (5.3,  ''),
    'CVE-2019-9193': (8.8,  'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2022-0543': (10.0, 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'),
    # ES
    'CVE-2014-3120': (7.5,  ''),
    'CVE-2015-1427': (7.5,  ''),
    # SNMP / telnet
    'CVE-2017-6736': (8.8,  'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'),
    'CVE-2011-4862': (10.0, ''),
}

# Severity → CVSS estimate for findings without a known CVE
SEVERITY_CVSS_ESTIMATE = {
    'CRITICAL': 9.5,
    'HIGH':     7.5,
    'MEDIUM':   5.5,
    'LOW':      3.5,
    'INFO':     1.0,
}

# Finding-type heuristic when MSF module isn't set
TYPE_ATTACK_MAP = {
    'web_path':          ['T1083'],
    'web_dir':           ['T1083'],
    'web_cms':           ['T1592'],
    'web_users':         ['T1087'],
    'web_plugin_vuln':   ['T1190'],
    'web_well_known':    ['T1592'],
    'web_oidc_disclosed':['T1592'],
    'web_vuln':          ['T1190'],
    'web_tech':          ['T1592'],
    'web_waf':           ['T1592'],
    'ad_users':          ['T1087.002'],
    'ad_enum':           ['T1087.002'],
    'smb_shares':        ['T1135'],
    'smb_share_listed':  ['T1135'],
    'smb_rpc_info':      ['T1592'],
    'ssl_vuln':          ['T1190'],
    'tls_legacy':        ['T1573.001'],
    'tls_weak_cipher':   ['T1573.001'],
    'dns_zone_xfer':     ['T1018'],
    'dns_subdomains':    ['T1018'],
}


# ── Public API ────────────────────────────────────────────────────────────────

def attack_techniques_for(msf_module: str | None,
                           finding_type: str = '') -> list[str]:
    """Return ATT&CK technique IDs for a finding.

    Resolution order: explicit MSF-module map → finding-type heuristic → [].
    """
    if msf_module and msf_module in MODULE_ATTACK_MAP:
        return list(MODULE_ATTACK_MAP[msf_module])
    return list(TYPE_ATTACK_MAP.get(finding_type, []))


def cvss_for(cve: str | None, severity: str = 'INFO') -> tuple[float, str]:
    """Return (score, vector) for a CVE or severity-based estimate."""
    if cve and cve in CVE_CVSS_MAP:
        return CVE_CVSS_MAP[cve]
    return (SEVERITY_CVSS_ESTIMATE.get(severity, 0.0), '')


def technique_label(technique_id: str) -> str:
    """Human-readable label for an ATT&CK technique ID."""
    return ATTACK_TECHNIQUES.get(technique_id, technique_id)


def annotate_finding(finding: dict) -> dict:
    """Return a *copy* of finding with attack_techniques + CVSS fields added."""
    out = dict(finding)
    techniques = attack_techniques_for(
        finding.get('msf_module'),
        finding.get('type', ''))
    score, vector = cvss_for(
        finding.get('cve'),
        finding.get('severity', 'INFO'))
    out['attack_techniques'] = techniques
    out['attack_labels']     = [technique_label(t) for t in techniques]
    out['cvss_score']        = score
    out['cvss_vector']       = vector
    return out


def attack_matrix(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings by ATT&CK technique. Annotates findings on the fly.

    Returns {'T1190': [finding, finding, ...], 'T1110.001': [...]}.
    Findings without any technique are bucketed under 'unmapped'.
    """
    matrix: dict[str, list[dict]] = {}
    for f in findings:
        ann = annotate_finding(f) if 'attack_techniques' not in f else f
        techniques = ann.get('attack_techniques') or []
        if not techniques:
            matrix.setdefault('unmapped', []).append(ann)
            continue
        for tech in techniques:
            matrix.setdefault(tech, []).append(ann)
    return matrix


def coverage_stats() -> dict:
    """How many techniques and CVEs are mapped — useful for the audit script."""
    return {
        'techniques_labeled':  len(ATTACK_TECHNIQUES),
        'modules_mapped':      len(MODULE_ATTACK_MAP),
        'cves_with_cvss':      len(CVE_CVSS_MAP),
        'finding_types_mapped':len(TYPE_ATTACK_MAP),
    }
