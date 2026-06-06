"""
H3x-Dash CveChain
Maps Nmap service/port data to known CVEs and Metasploit modules.
Local lookup — no external API required for base operation.
"""

# ── CVE / MSF mapping table ───────────────────────────────────────────────────
# Format: service_key -> list of (CVE | None, MSF module | None, description, severity)

CVE_MAP: dict[str, list[tuple]] = {

    'smb': [
        ('CVE-2017-0144', 'exploit/windows/smb/ms17_010_eternalblue',
         'EternalBlue SMBv1 RCE — WannaCry / NotPetya vector', 'CRITICAL'),
        ('CVE-2017-0145', 'exploit/windows/smb/ms17_010_psexec',
         'EternalRomance / EternalSynergy SMBv1 RCE', 'CRITICAL'),
        ('CVE-2020-0796', 'exploit/windows/smb/cve_2020_0796_smbghost',
         'SMBGhost — SMBv3 Compression RCE (pre-auth)', 'CRITICAL'),
        ('CVE-2017-7494', 'exploit/linux/samba/is_known_pipename',
         'SambaCry — Samba 3.5.0–4.6.4 pre-auth RCE', 'CRITICAL'),
        ('CVE-2007-2447', 'exploit/multi/samba/usermap_script',
         'Samba 3.0.20 username map script command exec (Metasploitable)', 'CRITICAL'),
        (None, 'auxiliary/scanner/smb/smb_ms17_010',
         'MS17-010 EternalBlue scanner (non-destructive check)', 'INFO'),
        (None, 'auxiliary/scanner/smb/smb_enumshares',
         'SMB share enumeration', 'INFO'),
        (None, 'auxiliary/scanner/smb/smb_enumusers',
         'SMB user enumeration', 'INFO'),
        (None, 'auxiliary/scanner/smb/smb_login',
         'SMB brute-force login', 'HIGH'),
    ],

    # Windows DCERPC endpoint mapper (port 135) — NOT Sun RPC portmapper.
    'dcerpc': [
        ('CVE-2020-1472', 'auxiliary/admin/dcerpc/cve_2020_1472_zerologon',
         'Zerologon — Netlogon AES auth bypass, full DC compromise', 'CRITICAL'),
        ('CVE-2021-1675', 'exploit/windows/dcerpc/cve_2021_1675_printnightmare',
         'PrintNightmare — Print Spooler RCE / LPE (CVE-2021-1675 / 34527)', 'CRITICAL'),
        ('CVE-2003-0352', 'exploit/windows/dcerpc/ms03_026_dcom',
         'MS03-026 DCOM RPC buffer overflow (legacy Win2000/XP)', 'CRITICAL'),
        (None, 'auxiliary/scanner/dcerpc/tcp_dcerpc_auditor',
         'DCERPC endpoint auditor / enumeration', 'INFO'),
    ],

    'winrm': [
        (None, 'auxiliary/scanner/winrm/winrm_auth_methods',
         'WinRM authentication method enumeration', 'INFO'),
        (None, 'auxiliary/scanner/winrm/winrm_login',
         'WinRM brute-force login', 'HIGH'),
        (None, 'auxiliary/scanner/winrm/winrm_cmd',
         'WinRM authenticated command execution (scanner)', 'HIGH'),
        (None, 'exploit/windows/winrm/winrm_script_exec',
         'WinRM script execution with valid credentials', 'CRITICAL'),
    ],

    'rdp': [
        ('CVE-2019-0708', 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce',
         'BlueKeep — RDP pre-auth RCE (unauthenticated)', 'CRITICAL'),
        ('CVE-2012-0002', 'auxiliary/dos/windows/rdp/ms12_020_maxchannelids',
         'MS12-020 RDP MaxChannelIDs DoS', 'HIGH'),
        ('CVE-2019-1182', None,
         'DejaBlue — RDP RCE (Windows 10 / Server 2019)', 'CRITICAL'),
        (None, 'auxiliary/scanner/rdp/rdp_scanner',
         'RDP service detection / NLA check', 'INFO'),
    ],

    'ftp': [
        ('CVE-2011-2523', 'exploit/unix/ftp/vsftpd_234_backdoor',
         'vsftpd 2.3.4 backdoor — instant root shell', 'CRITICAL'),
        ('CVE-2010-4221', 'exploit/linux/ftp/proftp_telnet_iac',
         'ProFTPD 1.3.2rc3 Telnet IAC buffer overflow RCE', 'HIGH'),
        (None, 'auxiliary/scanner/ftp/ftp_login',
         'FTP brute-force login', 'HIGH'),
        (None, 'auxiliary/scanner/ftp/anonymous',
         'FTP anonymous access check', 'MEDIUM'),
    ],

    'ssh': [
        ('CVE-2023-38408', None,
         'OpenSSH ssh-agent remote code execution', 'CRITICAL'),
        ('CVE-2018-15473', None,
         'OpenSSH username enumeration (timing oracle)', 'MEDIUM'),
        ('CVE-2016-6515', None,
         'OpenSSH PAM login DoS via excessive authentication', 'MEDIUM'),
        (None, 'auxiliary/scanner/ssh/ssh_login',
         'SSH brute-force login', 'HIGH'),
        (None, 'auxiliary/scanner/ssh/ssh_enumusers',
         'SSH username enumeration', 'MEDIUM'),
    ],

    'http': [
        # ── Apache & shell legacy ────────────────────────────────────────────
        ('CVE-2021-41773', 'exploit/multi/http/apache_normalize_path_rce',
         'Apache 2.4.49 path traversal / RCE', 'CRITICAL'),
        ('CVE-2021-42013', 'exploit/multi/http/apache_normalize_path_rce',
         'Apache 2.4.50 path traversal bypass / RCE', 'CRITICAL'),
        ('CVE-2014-6271', 'exploit/multi/http/apache_mod_cgi_bash_env_exec',
         'Shellshock — Apache mod_cgi bash env RCE', 'CRITICAL'),
        # ── Java app stack (Log4j / Struts / Spring / Confluence) ───────────
        ('CVE-2021-44228', 'exploit/multi/http/log4shell_header_injection',
         'Log4Shell — Log4j2 JNDI lookup RCE via HTTP headers', 'CRITICAL'),
        (None, 'auxiliary/scanner/http/log4shell_scanner',
         'Log4Shell vulnerability scanner', 'HIGH'),
        ('CVE-2017-5638', 'exploit/multi/http/struts2_content_type_ognl',
         'Apache Struts2 Content-Type OGNL RCE', 'CRITICAL'),
        ('CVE-2022-22965', 'exploit/multi/http/spring_framework_rce_spring4shell',
         'Spring4Shell — Spring Framework RCE', 'CRITICAL'),
        ('CVE-2022-26134', 'exploit/multi/http/atlassian_confluence_webwork_ognl_injection',
         'Confluence OGNL injection pre-auth RCE', 'CRITICAL'),
        # ── PHP-FPM ──────────────────────────────────────────────────────────
        ('CVE-2019-11043', 'exploit/multi/http/php_fpm_rce',
         'PHP-FPM PATH_INFO buffer overflow RCE (Nginx configs)', 'CRITICAL'),
        # ── Tomcat (HTTP-side; AJP lives under the "ajp" key) ───────────────
        (None, 'auxiliary/scanner/http/tomcat_mgr_login',
         'Tomcat Manager brute-force login', 'HIGH'),
        (None, 'exploit/multi/http/tomcat_mgr_upload',
         'Tomcat Manager authenticated WAR upload RCE', 'CRITICAL'),
        (None, 'exploit/multi/http/tomcat_jsp_upload_bypass',
         'Tomcat JSP upload auth bypass RCE', 'CRITICAL'),
        # ── GitLab / Jenkins ────────────────────────────────────────────────
        ('CVE-2021-22205', 'exploit/multi/http/gitlab_exif_rce',
         'GitLab CE/EE ExifTool RCE (unauthenticated)', 'CRITICAL'),
        (None, 'exploit/multi/http/jenkins_script_console',
         'Jenkins authenticated Groovy script console RCE', 'HIGH'),
        # ── CMS targets ─────────────────────────────────────────────────────
        ('CVE-2018-7600', 'exploit/unix/webapp/drupal_drupalgeddon2',
         'Drupalgeddon2 — Drupal Form API pre-auth RCE', 'CRITICAL'),
        (None, 'auxiliary/scanner/http/wordpress_login_enum',
         'WordPress user enumeration / brute-force', 'MEDIUM'),
        # ── JBoss ───────────────────────────────────────────────────────────
        (None, 'exploit/multi/http/jboss_invoke_deploy',
         'JBoss JMX-Console authenticated WAR deploy', 'CRITICAL'),
        # ── IIS / WebDAV ────────────────────────────────────────────────────
        (None, 'auxiliary/scanner/http/webdav_scanner',
         'WebDAV scanner — methods enumeration', 'MEDIUM'),
        (None, 'exploit/windows/iis/iis_webdav_upload_asp',
         'IIS WebDAV authenticated ASP upload RCE', 'HIGH'),
        # ── Generic enum ────────────────────────────────────────────────────
        (None, 'auxiliary/scanner/http/http_version',
         'HTTP banner / version detection', 'INFO'),
        (None, 'auxiliary/scanner/http/dir_scanner',
         'HTTP directory brute-force', 'INFO'),
    ],

    # Tomcat AJP connector (port 8009) — Ghostcat file disclosure / RCE.
    'ajp': [
        ('CVE-2020-1938', 'auxiliary/admin/http/tomcat_ghostcat',
         'Ghostcat — Tomcat AJP file disclosure / RCE', 'HIGH'),
    ],

    # Java RMI Registry (port 1099) — insecure default config RCE.
    'rmi': [
        (None, 'exploit/multi/misc/java_rmi_server',
         'Java RMI Server insecure default config RCE', 'CRITICAL'),
    ],

    # UnrealIRCd backdoor (port 6667) — Metasploitable 2 classic.
    'irc': [
        ('CVE-2010-2075', 'exploit/unix/irc/unreal_ircd_3281_backdoor',
         'UnrealIRCd 3.2.8.1 backdoor command execution', 'CRITICAL'),
    ],

    # distccd v1 command execution (port 3632) — Metasploitable 2 classic.
    'distcc': [
        ('CVE-2004-2687', 'exploit/unix/misc/distcc_exec',
         'distccd v1 command execution (Metasploitable classic)', 'CRITICAL'),
    ],

    # DNS — zone transfer / enum (port 53). Was a dead route before.
    'dns': [
        (None, 'auxiliary/gather/enum_dns',
         'DNS zone enumeration / AXFR / subdomain harvest', 'MEDIUM'),
    ],

    # POP3 / IMAP — were previously mis-aliased to smtp.
    'pop3': [
        (None, 'auxiliary/scanner/pop3/pop3_login',
         'POP3 brute-force login', 'HIGH'),
    ],

    'imap': [
        (None, 'auxiliary/scanner/imap/imap_version',
         'IMAP server banner / version detection', 'INFO'),
    ],

    'telnet': [
        ('CVE-2011-4862', 'exploit/freebsd/telnet/telnet_encrypt_keyid',
         'BSD telnetd encrypt option buffer overflow', 'CRITICAL'),
        (None, 'auxiliary/scanner/telnet/telnet_login',
         'Telnet brute-force login', 'HIGH'),
        (None, None, 'Telnet transmits credentials in cleartext', 'HIGH'),
    ],

    'mssql': [
        (None, 'auxiliary/scanner/mssql/mssql_login',
         'MSSQL brute-force login', 'HIGH'),
        (None, 'exploit/windows/mssql/mssql_payload',
         'MSSQL xp_cmdshell payload execution (requires SA)', 'CRITICAL'),
        (None, 'auxiliary/scanner/mssql/mssql_hashdump',
         'MSSQL password hash dump', 'HIGH'),
        (None, 'auxiliary/admin/mssql/mssql_enum',
         'MSSQL enumeration — databases, users, configs', 'INFO'),
    ],

    'mysql': [
        ('CVE-2012-2122', 'auxiliary/scanner/mysql/mysql_authbypass_hashdump',
         'MySQL auth bypass via timing attack', 'HIGH'),
        (None, 'auxiliary/scanner/mysql/mysql_login',
         'MySQL brute-force login', 'HIGH'),
        (None, 'auxiliary/scanner/mysql/mysql_hashdump',
         'MySQL user password hash dump', 'HIGH'),
        (None, 'auxiliary/scanner/mysql/mysql_writable_dirs',
         'MySQL writable directory check (FILE privilege)', 'MEDIUM'),
    ],

    'vnc': [
        (None, 'auxiliary/scanner/vnc/vnc_none_auth',
         'VNC no-authentication check', 'CRITICAL'),
        (None, 'auxiliary/scanner/vnc/vnc_login',
         'VNC brute-force login', 'HIGH'),
    ],

    'snmp': [
        (None, 'auxiliary/scanner/snmp/snmp_enum',
         'SNMP community string enumeration (v1/v2c)', 'HIGH'),
        (None, 'auxiliary/scanner/snmp/snmp_enumshares',
         'SNMP share enumeration', 'MEDIUM'),
        (None, 'auxiliary/scanner/snmp/snmp_login',
         'SNMP community string brute-force', 'HIGH'),
        ('CVE-2017-6736', None,
         'Cisco IOS SNMP remote code execution', 'CRITICAL'),
    ],

    'redis': [
        (None, 'exploit/linux/redis/redis_replication_cmd_exec',
         'Redis unauthenticated RCE via replication', 'CRITICAL'),
        ('CVE-2022-0543', None,
         'Redis Lua sandbox escape (Debian/Ubuntu packaging) — CVE-only, '
         'no stock MSF module', 'CRITICAL'),
        (None, None,
         'Redis unauthenticated access — check for no-auth config', 'CRITICAL'),
    ],

    'elasticsearch': [
        ('CVE-2014-3120', 'exploit/multi/elasticsearch/search_groovy_script',
         'Elasticsearch dynamic script RCE (< 1.3.8)', 'CRITICAL'),
        ('CVE-2015-1427', 'exploit/multi/elasticsearch/script_mvel_rce',
         'Elasticsearch Groovy sandbox bypass RCE (< 1.6.1)', 'CRITICAL'),
        (None, None,
         'Elasticsearch unauthenticated access — check for open cluster', 'HIGH'),
    ],

    'mongodb': [
        (None, 'auxiliary/gather/mongodb_js_inject_collection_enum',
         'MongoDB JS injection / collection enumeration', 'MEDIUM'),
        (None, None,
         'MongoDB unauthenticated access — no-auth default config', 'CRITICAL'),
    ],

    'ldap': [
        (None, 'auxiliary/gather/ldap_query',
         'LDAP anonymous bind / directory enumeration', 'HIGH'),
        (None, 'auxiliary/scanner/ldap/ldap_login',
         'LDAP brute-force login', 'HIGH'),
    ],

    'psql': [
        (None, 'auxiliary/scanner/postgres/postgres_login',
         'PostgreSQL brute-force login', 'HIGH'),
        ('CVE-2019-9193', None,
         'PostgreSQL COPY FROM/TO PROGRAM RCE (superuser required)', 'HIGH'),
        (None, 'auxiliary/scanner/postgres/postgres_hashdump',
         'PostgreSQL password hash dump', 'HIGH'),
    ],

    'oracle': [
        (None, 'auxiliary/scanner/oracle/oracle_login',
         'Oracle DB brute-force login (requires oracle_client)', 'HIGH'),
        (None, 'auxiliary/admin/oracle/oraenum',
         'Oracle DB enumeration', 'INFO'),
    ],

    # Sun RPC portmapper (port 111 — Linux/Unix). Windows port 135 is a
    # different beast — see the 'dcerpc' key.
    'rpcbind': [
        (None, 'auxiliary/scanner/misc/sunrpc_portmapper',
         'RPC portmapper service enumeration', 'INFO'),
        (None, None, 'rpcbind exposed — check for NFS mounts', 'MEDIUM'),
    ],

    'nfs': [
        (None, 'auxiliary/scanner/nfs/nfsmount',
         'NFS mount enumeration — check for world-readable exports', 'HIGH'),
    ],

    'smtp': [
        (None, 'auxiliary/scanner/smtp/smtp_enum',
         'SMTP user enumeration via VRFY / EXPN / RCPT', 'MEDIUM'),
        (None, 'auxiliary/scanner/smtp/smtp_relay',
         'SMTP open relay check', 'HIGH'),
    ],

    'backdoor': [
        (None, 'exploit/multi/handler',
         'Port 4444 — likely an active backdoor or reverse shell listener', 'CRITICAL'),
    ],
}

# ── Port → service key mapping ────────────────────────────────────────────────

PORT_TO_SERVICE: dict[int, str] = {
    21:    'ftp',
    22:    'ssh',
    23:    'telnet',
    25:    'smtp',
    53:    'dns',
    80:    'http',
    110:   'pop3',
    111:   'rpcbind',
    135:   'dcerpc',         # Windows DCERPC endpoint mapper (NOT Sun RPC)
    139:   'smb',
    143:   'imap',
    161:   'snmp',
    389:   'ldap',
    443:   'http',
    445:   'smb',
    # 512: rexec — r-service, not SSH
    # 513: rlogin — r-service, not SSH
    # 514: rsh — r-service, not SSH
    631:   'http',
    993:   'imap',           # imaps
    995:   'pop3',           # pop3s
    1099:  'rmi',            # Java RMI Registry
    1433:  'mssql',
    1521:  'oracle',
    2049:  'nfs',
    3306:  'mysql',
    3389:  'rdp',
    3632:  'distcc',         # distccd command exec — Metasploitable classic
    4444:  'backdoor',
    5432:  'psql',
    5900:  'vnc',
    5985:  'winrm',          # WinRM HTTP
    5986:  'winrm',          # WinRM HTTPS
    6379:  'redis',
    6667:  'irc',            # UnrealIRCd backdoor target
    8009:  'ajp',            # Tomcat AJP — Ghostcat
    8080:  'http',
    8443:  'http',
    9200:  'elasticsearch',
    27017: 'mongodb',
}

# Service name aliases (from Nmap banners → internal key)
SERVICE_ALIAS: dict[str, str] = {
    'microsoft-ds':   'smb',
    'netbios-ssn':    'smb',
    'ms-wbt-server':  'rdp',
    'domain':         'dns',
    'ftp-data':       'ftp',
    'postgresql':     'psql',
    'http-proxy':     'http',
    'ssl/http':       'http',
    'https':          'http',
    'http-alt':       'http',
    # Windows-stack banner aliases
    'msrpc':          'dcerpc',
    'epmap':          'dcerpc',
    'wsman':          'winrm',
    'wsmans':         'winrm',
    # Java / app server banners
    'rmiregistry':    'rmi',
    'java-rmi':       'rmi',
    'ajp13':          'ajp',
    # IRC / distcc banners
    'distccd':        'distcc',
    'ircd':           'irc',
    'ircu':           'irc',
}

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

# ── Per-module correct RPORT ───────────────────────────────────────────────────
# The port that triggered a CVE suggestion (e.g. 139/NetBIOS) is often NOT the
# correct RPORT for the MSF module.  ms17_010_* MUST use 445, not 139.
MSF_PORT_OVERRIDES: dict[str, int] = {
    # SMB family — ms17_010_* MUST use 445, not 139.
    'exploit/windows/smb/ms17_010_eternalblue':         445,
    'exploit/windows/smb/ms17_010_psexec':              445,
    'exploit/windows/smb/cve_2020_0796_smbghost':       445,
    'exploit/linux/samba/is_known_pipename':            445,
    'exploit/multi/samba/usermap_script':               139,
    'auxiliary/scanner/smb/smb_ms17_010':               445,
    'auxiliary/scanner/smb/smb_enumshares':             445,
    'auxiliary/scanner/smb/smb_enumusers':              445,
    'auxiliary/scanner/smb/smb_login':                  445,
    # DCERPC — Zerologon/PrintNightmare ride the SMB-pipe path (445)
    'auxiliary/admin/dcerpc/cve_2020_1472_zerologon':   445,
    'exploit/windows/dcerpc/cve_2021_1675_printnightmare': 445,
    'exploit/windows/dcerpc/ms03_026_dcom':             135,
    'auxiliary/scanner/dcerpc/tcp_dcerpc_auditor':      135,
    # WinRM
    'auxiliary/scanner/winrm/winrm_auth_methods':       5985,
    'auxiliary/scanner/winrm/winrm_login':              5985,
    'auxiliary/scanner/winrm/winrm_cmd':                5985,
    'exploit/windows/winrm/winrm_script_exec':          5985,
    # RDP
    'exploit/windows/rdp/cve_2019_0708_bluekeep_rce':   3389,
    'auxiliary/dos/windows/rdp/ms12_020_maxchannelids':       3389,
    'auxiliary/scanner/rdp/rdp_scanner':                3389,
    # FTP
    'exploit/unix/ftp/vsftpd_234_backdoor':             21,
    'exploit/linux/ftp/proftp_telnet_iac':              21,
    'auxiliary/scanner/ftp/ftp_login':                  21,
    'auxiliary/scanner/ftp/anonymous':                  21,
    # Java RMI / distcc / IRC / AJP
    'exploit/multi/misc/java_rmi_server':               1099,
    'exploit/unix/misc/distcc_exec':                    3632,
    'exploit/unix/irc/unreal_ircd_3281_backdoor':       6667,
    'auxiliary/admin/http/tomcat_ghostcat':             8009,
    # Databases
    'exploit/linux/redis/redis_replication_cmd_exec':   6379,
    'exploit/multi/elasticsearch/search_groovy_script': 9200,
    'exploit/multi/elasticsearch/script_mvel_rce':      9200,
    'auxiliary/scanner/mysql/mysql_login':              3306,
    'auxiliary/scanner/mysql/mysql_hashdump':           3306,
    'auxiliary/scanner/mssql/mssql_login':              1433,
    'exploit/windows/mssql/mssql_payload':              1433,
    'auxiliary/scanner/postgres/postgres_login':        5432,
    # Misc auth-scanners
    'auxiliary/scanner/vnc/vnc_none_auth':              5900,
    'auxiliary/scanner/vnc/vnc_login':                  5900,
    'auxiliary/scanner/snmp/snmp_enum':                 161,
    'auxiliary/scanner/ldap/ldap_login':                389,
    'auxiliary/gather/ldap_query':                      389,
    'auxiliary/scanner/ssh/ssh_login':                  22,
    'auxiliary/scanner/ssh/ssh_enumusers':              22,
    'auxiliary/scanner/telnet/telnet_login':            23,
    # Mail
    'auxiliary/scanner/pop3/pop3_login':                110,
    'auxiliary/scanner/imap/imap_version':              143,
    # DNS
    'auxiliary/gather/enum_dns':                        53,
}

# ── MSF module rank (for sorting — higher is better) ─────────────────────────
MSF_RANK_SCORE: dict[str, int] = {
    'excellent': 6, 'great': 5, 'good': 4,
    'normal': 3, 'average': 2, 'low': 1, 'manual': 0,
}

# Static rank table for key modules (used when MSF RPC is offline)
MSF_MODULE_RANK: dict[str, str] = {
    # SMB / Samba
    'exploit/windows/smb/ms17_010_eternalblue':         'great',
    'exploit/windows/smb/ms17_010_psexec':              'normal',
    'exploit/windows/smb/cve_2020_0796_smbghost':       'average',
    'exploit/linux/samba/is_known_pipename':            'average',
    'exploit/multi/samba/usermap_script':               'excellent',
    # DCERPC / Windows
    'exploit/windows/dcerpc/cve_2021_1675_printnightmare': 'good',
    'exploit/windows/dcerpc/ms03_026_dcom':             'great',
    'exploit/windows/winrm/winrm_script_exec':          'great',
    # RDP
    'exploit/windows/rdp/cve_2019_0708_bluekeep_rce':   'great',
    # Metasploitable / vulnerable lab classics
    'exploit/unix/ftp/vsftpd_234_backdoor':             'excellent',
    'exploit/unix/irc/unreal_ircd_3281_backdoor':       'excellent',
    'exploit/unix/misc/distcc_exec':                    'excellent',
    'exploit/multi/misc/java_rmi_server':               'excellent',
    # Databases / data stores
    'exploit/linux/redis/redis_replication_cmd_exec':   'great',
    # Web app stack
    'exploit/multi/http/apache_normalize_path_rce':     'excellent',
    'exploit/multi/http/struts2_content_type_ognl':     'excellent',
    'exploit/multi/http/spring_framework_rce_spring4shell': 'excellent',
    'exploit/multi/http/log4shell_header_injection':    'great',
    'exploit/multi/http/tomcat_mgr_upload':             'excellent',
    'exploit/multi/http/tomcat_jsp_upload_bypass':      'excellent',
    'exploit/multi/http/atlassian_confluence_webwork_ognl_injection': 'excellent',
    'exploit/multi/http/gitlab_exif_rce':               'excellent',
    'exploit/multi/http/jenkins_script_console':        'excellent',
    'exploit/unix/webapp/drupal_drupalgeddon2':         'excellent',
    'exploit/multi/http/jboss_invoke_deploy':           'excellent',
    'exploit/windows/iis/iis_webdav_upload_asp':        'great',
}

# ── Suggested payloads per target platform ────────────────────────────────────
# The 'multi' default is cmd/unix/reverse_bash because every exploit/multi/*
# module in this chain (Samba usermap, Log4Shell, Spring4Shell, Apache
# Shellshock, Struts2, etc.) runs against Linux/Unix targets in practice —
# the historical Windows default produced unloadable payloads against the
# entire Metasploitable 2/3 set and was the silent #1 cause of "exploit
# fires but no session."
MSF_PLATFORM_PAYLOAD: dict[str, str] = {
    'windows': 'windows/x64/meterpreter/reverse_tcp',
    'linux':   'linux/x64/meterpreter/reverse_tcp',
    'unix':    'cmd/unix/reverse_bash',
    'multi':   'cmd/unix/reverse_bash',
    'java':    'java/meterpreter/reverse_tcp',
    'osx':     'osx/x64/meterpreter/reverse_tcp',
}


# Per-module payload overrides — these modules have known-good payloads that
# the platform-based default gets wrong. Reviewed against MSF documentation
# and tested against Metasploitable 2/3 reliable-exploit list.
MSF_MODULE_PAYLOAD_OVERRIDE: dict[str, str] = {
    # vsftpd backdoor opens a shell on port 6200 — no reverse callback;
    # MSF connects directly to the opened backdoor.
    'exploit/unix/ftp/vsftpd_234_backdoor':            'cmd/unix/interact',
    # IRC + distcc + Samba — classic command-exec, cmd/unix/reverse_bash is
    # the most reliable payload (works without arch detection).
    'exploit/unix/irc/unreal_ircd_3281_backdoor':      'cmd/unix/reverse_bash',
    'exploit/unix/misc/distcc_exec':                   'cmd/unix/reverse_bash',
    'exploit/multi/samba/usermap_script':              'cmd/unix/reverse_bash',
    # Java RMI deserialization → Java payload
    'exploit/multi/misc/java_rmi_server':              'java/meterpreter/reverse_tcp',
    # Web app RCEs — cmd/unix/reverse_bash is the most universal
    'exploit/multi/http/log4shell_header_injection':   'cmd/unix/reverse_bash',
    'exploit/multi/http/struts2_content_type_ognl':    'cmd/unix/reverse_bash',
    'exploit/multi/http/spring_framework_rce_spring4shell': 'cmd/unix/reverse_bash',
    'exploit/multi/http/atlassian_confluence_webwork_ognl_injection': 'cmd/unix/reverse_bash',
    'exploit/multi/http/apache_mod_cgi_bash_env_exec': 'cmd/unix/reverse_bash',
    'exploit/multi/http/apache_normalize_path_rce':    'cmd/unix/reverse_bash',
    'exploit/multi/http/php_fpm_rce':                  'cmd/unix/reverse_bash',
    'exploit/multi/http/jenkins_script_console':       'cmd/unix/reverse_bash',
    'exploit/multi/http/gitlab_exif_rce':              'cmd/unix/reverse_bash',
    'exploit/unix/webapp/drupal_drupalgeddon2':        'cmd/unix/reverse_bash',
    # Tomcat: target is typically Linux/Java; web shell upload then JSP exec
    'exploit/multi/http/tomcat_mgr_upload':            'java/meterpreter/reverse_tcp',
    'exploit/multi/http/tomcat_jsp_upload_bypass':     'java/meterpreter/reverse_tcp',
    # Redis Lua sandbox escape — runs OS commands on the Linux Redis host
    'exploit/linux/redis/redis_replication_cmd_exec':  'cmd/unix/reverse_bash',
    # ── Windows SMB kernel exploits are x64-NATIVE ─────────────────────────────
    # ms17_010_eternalblue and SMBGhost only target 64-bit kernels and only
    # accept windows/x64/* payloads. Handing them the x86 payload
    # (windows/meterpreter/reverse_tcp) triggers MSF's "not compatible" rejection.
    # Force x64 here so flaky arch detection can't downgrade them to x86.
    'exploit/windows/smb/ms17_010_eternalblue':        'windows/x64/meterpreter/reverse_tcp',
    'exploit/windows/smb/cve_2020_0796_smbghost':      'windows/x64/meterpreter/reverse_tcp',
}


def smart_payload(msf_module: str, host_os: str = '', host_arch: str = '') -> str:
    """
    Select the most reliable payload for a module given the actual target.

    Resolution order:
      1. Per-module override (curated, highest confidence)
      2. Host OS from nmap (matches reality, not module-path-inferred platform)
      3. Module-path-inferred platform (existing behavior, lowest confidence)
    """
    if not msf_module:
        return ''

    # 1. Curated per-module override
    if msf_module in MSF_MODULE_PAYLOAD_OVERRIDE:
        return MSF_MODULE_PAYLOAD_OVERRIDE[msf_module]

    # 2. Use actual target OS if scan detected it.
    #    Default to x64 — it's the overwhelming reality on modern Windows AND
    #    Linux. Only drop to x86 when the scan EXPLICITLY detected a 32-bit
    #    target. The old logic did the reverse (default x86 unless x64 proven),
    #    which handed x64-native exploits like eternalblue an x86 payload
    #    whenever arch detection was fuzzy — the #1 "not compatible" cause.
    host_os_lower   = (host_os or '').lower()
    host_arch_lower = (host_arch or '').lower()
    is_x86 = ('x86' in host_arch_lower or 'i386' in host_arch_lower
              or 'i686' in host_arch_lower or '32-bit' in host_arch_lower
              or '32 bit' in host_arch_lower)
    if 'windows' in host_os_lower:
        return ('windows/meterpreter/reverse_tcp' if is_x86
                else 'windows/x64/meterpreter/reverse_tcp')
    if 'linux' in host_os_lower:
        return ('linux/x86/meterpreter/reverse_tcp' if is_x86
                else 'linux/x64/meterpreter/reverse_tcp')

    # 3. Fall back to module-path inference
    platform = _module_platform(msf_module)
    return MSF_PLATFORM_PAYLOAD.get(platform, MSF_PLATFORM_PAYLOAD['multi'])

def _module_platform(msf_module: str) -> str:
    """Infer target platform from module path."""
    if msf_module is None:
        return 'multi'
    parts = msf_module.lower().split('/')
    for p in parts:
        if p in ('windows', 'linux', 'unix', 'osx', 'bsd', 'android'):
            return p
    return 'multi'


# ── CveChain ──────────────────────────────────────────────────────────────────

class CveChain:

    def suggest(self, host: dict, ports: list,
                enum_findings: list | None = None,
                host_classes: list[str] | None = None) -> list:
        """
        Return ranked CVE/MSF suggestions for a host's open ports.

        Enrichments over the base lookup:
        - msf_rport   : correct RPORT for the module (not the trigger port)
        - msf_rank    : reliability rank (excellent/great/good/normal/...)
        - msf_platform: target platform inferred from module path
        - msf_payload : suggested payload for this platform
        - enum_confirmed: True when an enum finding explicitly flagged this vuln
        - sort key    : enum_confirmed > severity > rank (best option surfaces first)

        Args:
            host_classes: optional list of class_ids from host_classifier.classify().
                          If provided, filters out modules that don't apply to
                          any of these classes. Universal/unmapped modules pass
                          through (no false negatives).
        """
        seen        = set()
        suggestions = []

        # Build a set of CVEs confirmed by enumeration for fast lookup
        confirmed_cves: set[str]     = set()
        confirmed_modules: set[str]  = set()
        if enum_findings:
            for f in enum_findings:
                if f.get('cve'):
                    confirmed_cves.add(f['cve'].upper())
                if f.get('msf_module'):
                    confirmed_modules.add(f['msf_module'])
                # NetExec SMBv1 → confirm EternalBlue family
                title = (f.get('title') or '').lower()
                if 'smbv1' in title and 'enabled' in title:
                    confirmed_modules.update({
                        'exploit/windows/smb/ms17_010_eternalblue',
                        'exploit/windows/smb/ms17_010_psexec',
                        'auxiliary/scanner/smb/smb_ms17_010',
                    })
                if 'smb signing' in title and ('disabled' in title or 'false' in title):
                    confirmed_modules.add('auxiliary/scanner/smb/smb_login')
                if 'redis' in title and 'unauth' in title:
                    confirmed_modules.update({
                        'exploit/linux/redis/redis_replication_cmd_exec',
                    })
                if 'anonymous' in title and 'ftp' in title:
                    confirmed_modules.add('auxiliary/scanner/ftp/anonymous')

        for port_info in ports:
            port_num = port_info.get('port')
            service  = (port_info.get('service') or '').lower().strip()
            version  = port_info.get('version', '')

            keys = []
            normalized = SERVICE_ALIAS.get(service, service)
            if normalized and normalized in CVE_MAP:
                keys.append(normalized)
            port_svc = PORT_TO_SERVICE.get(port_num)
            if port_svc and port_svc not in keys and port_svc in CVE_MAP:
                keys.append(port_svc)

            for key in keys:
                for cve, msf_module, desc, severity in CVE_MAP.get(key, []):
                    # uid keyed on CVE+module only — port_num omitted so the
                    # same vuln triggered by both port 139 AND 445 deduplicates.
                    uid = f"{cve or ''}{msf_module or ''}"
                    if uid in seen:
                        continue
                    seen.add(uid)

                    # Correct RPORT — override trigger port with module-specific value
                    msf_rport    = MSF_PORT_OVERRIDES.get(msf_module, port_num) if msf_module else port_num
                    msf_rank     = MSF_MODULE_RANK.get(msf_module or '', 'normal')
                    msf_platform = _module_platform(msf_module)
                    # smart_payload uses (in order): per-module override → actual
                    # nmap-detected host OS → module-path-inferred platform.
                    # This fixes the bug where every exploit/multi/* defaulted
                    # to a Windows payload regardless of target.
                    host_os      = (host.get('os') if host else '') or ''
                    host_arch    = (host.get('arch') if host else '') or ''
                    msf_payload  = smart_payload(msf_module or '', host_os, host_arch)
                    confirmed    = (
                        bool(msf_module and msf_module in confirmed_modules) or
                        bool(cve and cve.upper() in confirmed_cves)
                    )

                    suggestions.append({
                        'port':           port_num,
                        'service':        service or key,
                        'version':        version,
                        'cve':            cve,
                        'msf_module':     msf_module,
                        'msf_rport':      msf_rport,
                        'msf_rank':       msf_rank,
                        'msf_platform':   msf_platform,
                        'msf_payload':    msf_payload,
                        'description':    desc,
                        'severity':       severity,
                        'enum_confirmed': confirmed,
                        'host_ip':        host.get('ip', '') if host else '',
                    })

        # Sort: enum_confirmed first, then severity, then rank (higher = better)
        suggestions.sort(key=lambda x: (
            0 if x['enum_confirmed'] else 1,
            SEVERITY_ORDER.get(x['severity'], 99),
            -MSF_RANK_SCORE.get(x['msf_rank'], 3),
        ))

        # ── Class filter ─────────────────────────────────────────────────────
        # If the caller supplied host_classes (from host_classifier), hide
        # suggestions whose msf_module doesn't apply to any of them. Modules
        # without an explicit class mapping pass through — we'd rather show a
        # working exploit than hide it by mistake.
        if host_classes:
            try:
                from modules import host_classifier as _hc
                suggestions = _hc.filter_modules(suggestions, host_classes)
            except Exception:
                pass    # never let filter failures break the chain

        return suggestions
