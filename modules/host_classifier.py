"""
host_classifier.py — Identify what KIND of system a target is.

The CVE chain suggests every module whose port matches an open port on the
target. Many of those modules don't apply — `samba_usermap_script` won't
help against a Windows DC even if SMB is open, and `eternalblue` is useless
against a Linux file server. The classifier solves this by:

  1. Scoring each potential class against the host's evidence:
       - OS detection from nmap -O
       - Open-port combinations (characteristic signatures)
       - Service banners and product strings

  2. Returning a ranked list of probable classes with confidence (0–100).

  3. Providing a module-to-class compatibility map so the chain can filter
     suggestions to only modules that could plausibly land on this kind of host.

Public API:
  classify(host)              -> list[dict]  # ranked, highest confidence first
  best_class(host)            -> str | None  # class_id of the top match
  module_applies(module, cls) -> bool
  filter_modules(suggestions, classes) -> list  # keep only applicable
  all_classes()               -> list[dict]    # for UI rendering
"""

from __future__ import annotations
from dataclasses import dataclass, field


# ── Class catalog ─────────────────────────────────────────────────────────────
# Each class is scored by:
#   high_signal_ports  — strong indicator. +30 each present.
#   expected_ports     — supporting indicator. +15 each present.
#   required_any       — at least one must be present, else class disqualified.
#   required_all       — all must be present, else class disqualified.
#   forbidden_ports    — if any present, class disqualified.
#   os_keywords        — substring match in nmap OS string. +40 each match.
#   service_keywords   — substring match in any service name. +20 each match.
#   banner_keywords    — substring match in any banner/product. +15 each match.
#   max_total_ports    — penalize if more open ports than this (specialization).

@dataclass
class HostClass:
    class_id:           str
    label:              str
    icon:               str
    description:        str
    high_signal_ports:  list[int] = field(default_factory=list)
    expected_ports:     list[int] = field(default_factory=list)
    required_any:       list[int] = field(default_factory=list)
    required_all:       list[int] = field(default_factory=list)
    forbidden_ports:    list[int] = field(default_factory=list)
    os_keywords:        list[str] = field(default_factory=list)
    service_keywords:   list[str] = field(default_factory=list)
    banner_keywords:    list[str] = field(default_factory=list)
    max_total_ports:    int | None = None


CLASSES: dict[str, HostClass] = {
    # ── Windows endpoints ─────────────────────────────────────────────────────
    'windows_workstation': HostClass(
        class_id='windows_workstation',
        label='Windows Workstation',
        icon='🖥️',
        description='Windows desktop/laptop (Win 7/8/10/11). NOT a domain '
                    'controller. Targets: SMB, RDP, WinRM, LPE chains.',
        high_signal_ports=[445, 3389],
        expected_ports=[135, 139, 5985, 5986],
        required_any=[445, 135, 3389],
        forbidden_ports=[88, 389],          # DC discriminators
        os_keywords=['windows 7', 'windows 8', 'windows 10', 'windows 11',
                     'microsoft windows'],
        service_keywords=['microsoft-ds', 'msrpc'],
    ),
    'windows_dc': HostClass(
        class_id='windows_dc',
        label='Windows Domain Controller',
        icon='🏛️',
        description='Active Directory domain controller. Targets: Zerologon, '
                    'PrintNightmare, Kerberoasting, DCSync, LDAP attacks.',
        high_signal_ports=[88, 389, 445],
        expected_ports=[53, 135, 139, 464, 593, 636, 3268, 3269, 5985, 5986],
        required_all=[88, 389],
        os_keywords=['windows server', 'domain controller', 'active directory'],
        service_keywords=['ldap', 'kerberos-sec', 'globalcatldap'],
    ),
    'windows_server': HostClass(
        class_id='windows_server',
        label='Windows Server (Member)',
        icon='🪟',
        description='Windows server, not a domain controller. Could be file '
                    'server, app server, web server, or generic member server.',
        high_signal_ports=[445, 3389, 5985],
        expected_ports=[135, 139, 80, 443],
        required_any=[445, 3389],
        forbidden_ports=[88],
        os_keywords=['windows server'],
        service_keywords=['microsoft-ds'],
    ),

    # ── Linux endpoints ───────────────────────────────────────────────────────
    'linux_server': HostClass(
        class_id='linux_server',
        label='Linux Server',
        icon='🐧',
        description='Linux server — generic. Targets: SSH, exposed services, '
                    'Samba (if shared), Linux kernel LPE post-shell.',
        high_signal_ports=[22],
        # Keep this list TIGHT — ports here pull confidence away from
        # specialized classes (web_application, database_server, mail_server,
        # linux_samba_host). Generic Linux server signal is just SSH + maybe
        # FTP. Specialized signals belong on their own classes.
        expected_ports=[21, 11211],
        required_any=[22, 21],
        forbidden_ports=[3389, 5985, 5986],
        os_keywords=['linux', 'ubuntu', 'debian', 'centos', 'red hat', 'rhel',
                     'fedora', 'alpine', 'arch'],
        service_keywords=['ssh', 'openssh'],
    ),
    'linux_samba_host': HostClass(
        class_id='linux_samba_host',
        label='Linux File Server (Samba)',
        icon='📁',
        description='Linux box running Samba — file/print sharing. Targets: '
                    'Samba-specific CVEs (usermap_script, SambaCry, '
                    'is_known_pipename) plus standard Linux server attacks.',
        high_signal_ports=[139, 445, 22],
        expected_ports=[111, 2049],         # NFS too sometimes
        required_all=[445],
        os_keywords=['linux', 'samba', 'unix'],
        service_keywords=['samba'],
        forbidden_ports=[3389, 5985],
        banner_keywords=['samba', 'unix samba'],
    ),

    # ── Web / application servers ─────────────────────────────────────────────
    'web_application': HostClass(
        class_id='web_application',
        label='Web Application Server',
        icon='🌐',
        description='Primarily web-facing — Tomcat, JBoss, Jenkins, GitLab, '
                    'Confluence, Drupal, WordPress, custom Java/PHP/Python. '
                    'Targets: Log4Shell, Spring4Shell, Struts2, framework RCEs.',
        high_signal_ports=[80, 443, 8080, 8443],
        expected_ports=[8000, 8009, 8888, 9090, 9200, 5000],
        required_any=[80, 443, 8080, 8443, 8000, 8888],
        service_keywords=['http', 'https', 'http-proxy'],
        banner_keywords=['apache', 'tomcat', 'nginx', 'jetty', 'iis',
                          'jenkins', 'gitlab', 'jboss', 'wildfly', 'drupal',
                          'wordpress', 'spring', 'confluence', 'php'],
    ),
    'database_server': HostClass(
        class_id='database_server',
        label='Database Server',
        icon='🗄️',
        description='Primarily a database. Targets: auth bypass, credential '
                    'brute, hashdump, COPY-PROGRAM RCE, redis replication.',
        high_signal_ports=[1433, 3306, 5432, 6379, 27017, 1521, 5984, 9200],
        required_any=[1433, 3306, 5432, 6379, 27017, 1521],
        service_keywords=['mssql', 'mysql', 'postgresql', 'redis', 'mongodb',
                          'oracle', 'couchdb'],
        max_total_ports=10,
    ),
    'mail_server': HostClass(
        class_id='mail_server',
        label='Mail Server',
        icon='✉️',
        description='SMTP/IMAP/POP3 server. Targets: user enum, open relay, '
                    'credential brute, Exim/Postfix CVEs.',
        high_signal_ports=[25, 465, 587, 143, 993, 110, 995],
        required_any=[25, 587, 143, 110, 993, 995],
        service_keywords=['smtp', 'submission', 'imap', 'pop3'],
        banner_keywords=['postfix', 'exim', 'sendmail', 'dovecot', 'exchange',
                          'zimbra'],
    ),

    # ── Network infrastructure ────────────────────────────────────────────────
    'network_device': HostClass(
        class_id='network_device',
        label='Network Device',
        icon='📡',
        description='Router/switch/firewall/VPN. Targets: SNMP enum, default '
                    'credentials, vendor-specific CVEs (Cisco/Fortinet/PAN/F5).',
        expected_ports=[22, 23, 80, 443, 161, 8080, 4786],
        required_any=[22, 23, 161],
        forbidden_ports=[445, 3306, 25, 3389],
        os_keywords=['cisco', 'juniper', 'fortinet', 'palo alto', 'pan-os',
                     'f5', 'big-ip', 'mikrotik', 'arista', 'ubiquiti', 'router',
                     'firewall', 'sonicwall', 'sophos'],
        service_keywords=['telnet'],
        banner_keywords=['cisco', 'fortigate', 'panos', 'big-ip'],
        max_total_ports=8,
    ),
    'printer': HostClass(
        class_id='printer',
        label='Network Printer',
        icon='🖨️',
        description='Network printer. Often leaks creds, sometimes pivot point.',
        high_signal_ports=[9100, 631, 515],
        expected_ports=[80, 443, 161, 21],
        required_any=[9100, 631, 515],
        os_keywords=['hp jetdirect', 'lexmark', 'xerox', 'brother', 'canon',
                     'epson', 'printer'],
        service_keywords=['jetdirect', 'ipp', 'printer'],
        banner_keywords=['jetdirect', 'laserjet', 'lexmark'],
        max_total_ports=8,
    ),
    'hypervisor_esxi': HostClass(
        class_id='hypervisor_esxi',
        label='ESXi Hypervisor',
        icon='💠',
        description='VMware ESXi host. Targets: vCenter CVEs, OpenSLP, '
                    'esxiArgs ransomware vector, SOAP exposed mgmt.',
        high_signal_ports=[443, 902],
        expected_ports=[80, 5988, 5989, 8000],
        required_any=[902, 5988, 5989],
        os_keywords=['vmware', 'esxi', 'esx'],
        service_keywords=['vmware-auth', 'vmware-fdm'],
        banner_keywords=['vmware', 'esxi'],
    ),
}


# ── Module-to-class compatibility ─────────────────────────────────────────────
# Each MSF module maps to the host classes where it could plausibly work.
# Empty list = unknown/universal (don't filter).
# Used by filter_modules() to hide irrelevant suggestions in the chain.

MODULE_CLASSES: dict[str, list[str]] = {
    # SMB / Windows
    'exploit/windows/smb/ms17_010_eternalblue':                ['windows_workstation', 'windows_server', 'windows_dc'],
    'exploit/windows/smb/ms17_010_psexec':                     ['windows_workstation', 'windows_server', 'windows_dc'],
    'exploit/windows/smb/cve_2020_0796_smbghost':              ['windows_workstation', 'windows_server', 'windows_dc'],
    'exploit/windows/smb/psexec':                              ['windows_workstation', 'windows_server', 'windows_dc'],
    'auxiliary/scanner/smb/smb_login':                         ['windows_workstation', 'windows_server', 'windows_dc', 'linux_samba_host'],
    'auxiliary/scanner/smb/smb_enumshares':                    ['windows_workstation', 'windows_server', 'windows_dc', 'linux_samba_host'],
    'auxiliary/scanner/smb/smb_enumusers':                     ['windows_workstation', 'windows_server', 'windows_dc'],
    'auxiliary/scanner/smb/smb_ms17_010':                      ['windows_workstation', 'windows_server', 'windows_dc'],
    'auxiliary/scanner/smb/smb_version':                       ['windows_workstation', 'windows_server', 'windows_dc', 'linux_samba_host'],

    # Samba on Linux
    'exploit/linux/samba/is_known_pipename':                   ['linux_samba_host'],
    'exploit/multi/samba/usermap_script':                      ['linux_samba_host'],

    # DCERPC / DC-specific
    'auxiliary/admin/dcerpc/cve_2020_1472_zerologon':          ['windows_dc'],
    'exploit/windows/dcerpc/cve_2021_1675_printnightmare':     ['windows_workstation', 'windows_server', 'windows_dc'],
    'exploit/windows/dcerpc/ms03_026_dcom':                    ['windows_workstation', 'windows_server'],

    # WinRM
    'exploit/windows/winrm/winrm_script_exec':                 ['windows_workstation', 'windows_server', 'windows_dc'],
    'auxiliary/scanner/winrm/winrm_login':                     ['windows_workstation', 'windows_server', 'windows_dc'],
    'auxiliary/scanner/winrm/winrm_auth_methods':              ['windows_workstation', 'windows_server', 'windows_dc'],

    # RDP
    'exploit/windows/rdp/cve_2019_0708_bluekeep_rce':          ['windows_workstation', 'windows_server'],
    'auxiliary/dos/windows/rdp/ms12_020_maxchannelids':        ['windows_workstation', 'windows_server'],

    # FTP
    'exploit/unix/ftp/vsftpd_234_backdoor':                    ['linux_server', 'linux_samba_host'],
    'exploit/freebsd/ftp/proftp_telnet_iac':                   ['linux_server'],
    'auxiliary/scanner/ftp/ftp_login':                         ['linux_server', 'linux_samba_host', 'windows_server', 'network_device'],
    'auxiliary/scanner/ftp/anonymous':                         ['linux_server', 'linux_samba_host', 'windows_server', 'network_device'],

    # SSH — applies broadly
    'auxiliary/scanner/ssh/ssh_login':                         ['linux_server', 'linux_samba_host', 'network_device', 'hypervisor_esxi'],
    'auxiliary/scanner/ssh/ssh_enumusers':                     ['linux_server', 'linux_samba_host'],

    # Web app exploits
    'exploit/multi/http/apache_normalize_path_rce':            ['web_application', 'linux_server'],
    'exploit/multi/http/apache_mod_cgi_bash_env_exec':         ['web_application', 'linux_server'],
    'exploit/multi/http/log4shell_header_injection':           ['web_application'],
    'auxiliary/scanner/http/log4shell_scanner':                ['web_application'],
    'exploit/multi/http/struts2_content_type_ognl':            ['web_application'],
    'exploit/multi/http/spring_framework_rce_spring4shell':    ['web_application'],
    'exploit/multi/http/atlassian_confluence_webwork_ognl_injection': ['web_application'],
    'exploit/multi/http/php_fpm_rce':                          ['web_application', 'linux_server'],
    'exploit/multi/http/tomcat_mgr_upload':                    ['web_application'],
    'exploit/multi/http/tomcat_jsp_upload_bypass':             ['web_application'],
    'exploit/multi/http/gitlab_exif_rce':                      ['web_application'],
    'exploit/multi/http/jenkins_script_console':               ['web_application'],
    'exploit/unix/webapp/drupal_drupalgeddon2':                ['web_application'],
    'exploit/multi/http/jboss_invoke_deploy':                  ['web_application'],
    'exploit/windows/iis/iis_webdav_upload_asp':               ['web_application', 'windows_server'],
    'auxiliary/scanner/http/wordpress_login_enum':             ['web_application'],
    'auxiliary/scanner/http/dir_listing':                      ['web_application'],
    'auxiliary/scanner/http/options':                          ['web_application'],

    # AJP / RMI / IRC / distcc
    'auxiliary/admin/http/tomcat_ghostcat':                    ['web_application'],
    'exploit/multi/misc/java_rmi_server':                      ['linux_server', 'linux_samba_host', 'windows_server', 'web_application'],
    'exploit/unix/irc/unreal_ircd_3281_backdoor':              ['linux_server', 'linux_samba_host'],
    'exploit/unix/misc/distcc_exec':                           ['linux_server', 'linux_samba_host'],

    # Databases
    'auxiliary/scanner/mssql/mssql_login':                     ['database_server', 'windows_server'],
    'exploit/windows/mssql/mssql_payload':                     ['database_server', 'windows_server'],
    'auxiliary/scanner/mssql/mssql_hashdump':                  ['database_server', 'windows_server'],
    'auxiliary/scanner/mysql/mysql_authbypass_hashdump':       ['database_server', 'linux_server'],
    'auxiliary/scanner/mysql/mysql_login':                     ['database_server', 'linux_server'],
    'auxiliary/scanner/mysql/mysql_hashdump':                  ['database_server', 'linux_server'],
    'auxiliary/scanner/postgres/postgres_login':               ['database_server', 'linux_server'],
    'auxiliary/scanner/postgres/postgres_hashdump':            ['database_server', 'linux_server'],
    'exploit/linux/redis/redis_replication_cmd_exec':          ['database_server', 'linux_server'],

    # VNC
    'auxiliary/scanner/vnc/vnc_none_auth':                     ['linux_server', 'windows_workstation', 'windows_server'],
    'auxiliary/scanner/vnc/vnc_login':                         ['linux_server', 'windows_workstation', 'windows_server'],

    # LDAP / SNMP / DNS / Mail
    'auxiliary/scanner/ldap/ldap_login':                       ['windows_dc', 'linux_server'],
    'auxiliary/gather/ldap_query':                             ['windows_dc'],
    'auxiliary/scanner/snmp/snmp_enum':                        ['network_device', 'printer', 'linux_server'],
    'auxiliary/scanner/snmp/snmp_login':                       ['network_device', 'printer'],
    'auxiliary/gather/enum_dns':                               ['windows_dc', 'linux_server', 'network_device'],
    'auxiliary/scanner/smtp/smtp_enum':                        ['mail_server', 'linux_server'],
    'auxiliary/scanner/smtp/smtp_relay':                       ['mail_server'],
    'auxiliary/scanner/pop3/pop3_login':                       ['mail_server'],
    'auxiliary/scanner/imap/imap_version':                     ['mail_server'],
    'auxiliary/scanner/telnet/telnet_login':                   ['network_device', 'linux_server', 'printer'],
}

# Host classes inherit module applicability from parent classes.
# Metasploitable-style boxes classify as linux_samba_host (Samba on 445) but
# still run distcc, UnrealIRCd, vsftpd, etc. — those modules are tagged
# linux_server and must not disappear when Samba wins the primary class.
CLASS_EXPANSION: dict[str, list[str]] = {
    'linux_samba_host': ['linux_server'],
}

# Primary-class-only filtering (not any() across alternates) prevents port-445
# ambiguity from leaking EternalBlue onto Samba hosts or usermap_script onto
# Windows workstations. CLASS_EXPANSION handles the linux_samba_host case
# without widening to unrelated alternates like windows_workstation.


# ── Classification engine ─────────────────────────────────────────────────────

def _ports_of(host: dict) -> set[int]:
    return {p['port'] for p in host.get('ports', [])
            if p.get('state', 'open') == 'open' and 'port' in p}


def _evidence(host: dict) -> tuple[set[int], str, set[str], set[str]]:
    """Extract (open_ports, os_lower, services_lower, banners_lower) from host."""
    open_ports = _ports_of(host)
    os_lower   = (host.get('os') or '').lower()
    services   = set()
    banners    = set()
    for p in host.get('ports', []):
        svc = (p.get('service') or '').lower()
        if svc:
            services.add(svc)
        for k in ('product', 'version', 'extrainfo', 'banner'):
            v = (p.get(k) or '').lower()
            if v:
                banners.add(v)
    return open_ports, os_lower, services, banners


def _score_class(spec: HostClass,
                  open_ports: set[int],
                  os_str: str,
                  services: set[str],
                  banners: set[str]) -> int | None:
    """Return score for one class against host evidence, or None if disqualified."""
    # Hard constraints
    if spec.required_all and not all(p in open_ports for p in spec.required_all):
        return None
    if spec.required_any and not any(p in open_ports for p in spec.required_any):
        return None
    if spec.forbidden_ports and any(p in open_ports for p in spec.forbidden_ports):
        return None

    score = 0
    score += 30 * sum(1 for p in spec.high_signal_ports if p in open_ports)
    score += 15 * sum(1 for p in spec.expected_ports    if p in open_ports)
    score += 40 * sum(1 for k in spec.os_keywords       if k in os_str)
    score += 20 * sum(1 for k in spec.service_keywords
                       if any(k in s for s in services))
    score += 15 * sum(1 for k in spec.banner_keywords
                       if any(k in b for b in banners))

    # Specialization penalty — if class expects a tight footprint but host
    # has many ports open, lower confidence.
    if spec.max_total_ports is not None and len(open_ports) > spec.max_total_ports:
        score -= 10 * (len(open_ports) - spec.max_total_ports)

    return max(0, score)


def classify(host: dict) -> list[dict]:
    """
    Classify a host. Returns ranked list of probable classes, highest first.
    Each entry is {class_id, label, icon, description, confidence (0-100)}.
    """
    if not host or not host.get('ports'):
        return [{'class_id': 'unknown', 'label': 'Unknown',
                 'icon': '❓', 'description': 'Not enough evidence to classify.',
                 'confidence': 0}]

    open_ports, os_str, services, banners = _evidence(host)
    results = []
    for class_id, spec in CLASSES.items():
        score = _score_class(spec, open_ports, os_str, services, banners)
        if score is None or score == 0:
            continue
        results.append({
            'class_id':    class_id,
            'label':       spec.label,
            'icon':        spec.icon,
            'description': spec.description,
            # raw_score preserves the actual discrimination strength;
            # confidence is the display-clamped version (0-100). Sort uses
            # raw_score so a 235-point match outranks a 100-point match
            # even though both display as 100%.
            '_raw_score':  score,
            'confidence':  min(100, score),
        })
    # Sort by raw score (uncapped) so dominant matches win cleanly
    results.sort(key=lambda r: r['_raw_score'], reverse=True)
    # Drop the internal field before returning
    for r in results:
        r.pop('_raw_score', None)
    if not results:
        return [{'class_id': 'unknown', 'label': 'Unknown',
                 'icon': '❓',
                 'description': 'No class matched. Treat all modules as candidates.',
                 'confidence': 0}]
    return results


def best_class(host: dict) -> str | None:
    """Return class_id of the top match, or None if confidence too low."""
    matches = classify(host)
    if not matches:
        return None
    top = matches[0]
    return top['class_id'] if top['confidence'] >= 30 else None


def _effective_classes(class_id: str) -> set[str]:
    """class_id plus any inherited parent classes (see CLASS_EXPANSION)."""
    out = {class_id}
    out.update(CLASS_EXPANSION.get(class_id, []))
    return out


def module_applies(msf_module: str, class_id: str) -> bool:
    """
    True if the MSF module could plausibly apply to a host of this class.
    Modules NOT in MODULE_CLASSES are treated as universal (always applies)
    — better to over-include than to silently hide a working exploit.
    """
    if not msf_module:
        return True
    if msf_module not in MODULE_CLASSES:
        return True   # unknown → assume applicable (no false-negative hiding)
    applicable = set(MODULE_CLASSES[msf_module])
    return bool(_effective_classes(class_id) & applicable)


def filter_modules(suggestions: list[dict],
                    classes: list[str],
                    min_confidence: int = 30) -> list[dict]:
    """
    Drop suggestions whose msf_module doesn't apply to this host's classes.
    Modules with no class mapping are kept (treated as universal).

    Uses classes[0] (highest-confidence match from classify()) with
    CLASS_EXPANSION so linux_samba_host inherits linux_server modules
    (distcc, vsftpd, IRC, etc.) without checking Windows alternates that
    port 445 routinely scores alongside Samba.

    Args:
        suggestions: list of dicts from CveChain.suggest() — each has 'msf_module'
        classes:     class_ids the host matched (highest-confidence first)
        min_confidence: ignored at this layer; caller decides whether to filter
    """
    if not classes:
        return list(suggestions)
    primary = classes[0]
    out = []
    for s in suggestions:
        mod = s.get('msf_module')
        if not mod:
            # Pure-info entries (no module) — always keep
            out.append(s)
            continue
        if mod not in MODULE_CLASSES:
            out.append(s)   # unmapped → universal, keep
            continue
        if module_applies(mod, primary):
            out.append(s)
    return out


def all_classes() -> list[dict]:
    """All class catalog entries for UI rendering."""
    return [{
        'class_id':    spec.class_id,
        'label':       spec.label,
        'icon':        spec.icon,
        'description': spec.description,
    } for spec in CLASSES.values()]


def class_label(class_id: str) -> str:
    """Pretty label for a class_id."""
    spec = CLASSES.get(class_id)
    return spec.label if spec else class_id
