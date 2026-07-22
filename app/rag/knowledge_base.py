"""Curated cybersecurity knowledge documents for RAG indexing."""

SECURITY_KNOWLEDGE_BASE = [
    # MITRE ATT&CK Techniques
    {
        "doc_id": "MITRE-T1190",
        "category": "MITRE_ATTACK",
        "title": "T1190: Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "content": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior. Applications facing the Internet include web servers, database servers, SSH, FTP, and remote management interfaces. Vulnerabilities such as Apache path traversal, unauthenticated Redis, or outdated Tomcat management services directly enable initial access."
    },
    {
        "doc_id": "MITRE-T1046",
        "category": "MITRE_ATTACK",
        "title": "T1046: Network Service Discovery",
        "tactic": "Discovery",
        "content": "Adversaries may attempt to get a listing of services running on remote hosts, including port scans and service enumeration. By querying open ports (e.g. 22, 80, 443, 3306, 6379, 8080) and grabbing banners, attackers identify active software versions, exposed internal portals, and potential targets for secondary exploitation."
    },
    {
        "doc_id": "MITRE-T1133",
        "category": "MITRE_ATTACK",
        "title": "T1133: External Remote Services",
        "tactic": "Initial Access / Persistence",
        "content": "Adversaries may leverage external-facing remote services (like SSH on port 22, VPN portals, or remote administration web interfaces) to initially access and/or persist within a network. Open remote services with weak authentication or outdated versions (e.g. OpenSSH regreSSHion or default credentials) allow unauthorized intrusion."
    },
    {
        "doc_id": "MITRE-T1021",
        "category": "MITRE_ATTACK",
        "title": "T1021: Remote Services",
        "tactic": "Lateral Movement",
        "content": "Adversaries may use valid accounts or vulnerabilities on remote services like SSH or RDP to move laterally across systems. Unrestricted access to SSH or internal administration interfaces increases lateral movement velocity across cloud and on-premise infrastructure."
    },

    # Vulnerability & CVE Intelligence
    {
        "doc_id": "CVE-2024-6387",
        "category": "CVE",
        "title": "CVE-2024-6387 (regreSSHion): OpenSSH Remote Code Execution",
        "tactic": "Initial Access",
        "content": "A signal handler race condition in OpenSSH server (sshd) versions prior to 9.8p1 allows unauthenticated remote attackers to execute arbitrary code as root on glibc-based Linux systems. Discovered when scanning OpenSSH 8.2p1 or earlier banners exposed on TCP port 22. Immediate remediation requires updating OpenSSH or restricting port 22 access via firewall/VPN."
    },
    {
        "doc_id": "CVE-2021-41773",
        "category": "CVE",
        "title": "CVE-2021-41773: Apache HTTP Server Path Traversal & RCE",
        "tactic": "Initial Access / Execution",
        "content": "A flaw in Apache HTTP Server 2.4.49 allows path traversal and remote code execution when CGI scripts are enabled. Attackers can map URLs to files outside the expected document root. Identified when Server header returns Apache/2.4.49."
    },
    {
        "doc_id": "VULN-REDIS-UNAUTH",
        "category": "VULN_INTELLIGENCE",
        "title": "Unauthenticated Public Redis Instance Exposure (Port 6379)",
        "tactic": "Initial Access / Impact",
        "content": "Redis servers running on TCP port 6379 without authentication requirements ('requirepass') exposed to the public network allow attackers to execute arbitrary commands, read/modify cached database records, or achieve remote code execution via SSH key writing or cron job injection."
    },
    {
        "doc_id": "VULN-TOMCAT-EXPOSED",
        "category": "VULN_INTELLIGENCE",
        "title": "Exposed Apache Tomcat Manager Portal (Port 8080)",
        "tactic": "Initial Access",
        "content": "Apache Tomcat server instances exposed on port 8080 or 8443 serving administrative manager applications without IP whitelisting or using default credentials allow remote deployment of malicious WAR files, leading to full web application compromise and server takeover."
    },
    {
        "doc_id": "VULN-MISSING-SEC-HEADERS",
        "category": "OWASP_TOP_10",
        "title": "OWASP A05:2021 - Security Misconfiguration (Missing Headers)",
        "tactic": "Defense Evasion / Initial Access",
        "content": "Web applications failing to enforce Strict-Transport-Security (HSTS), Content-Security-Policy (CSP), or X-Frame-Options headers suffer from security misconfiguration. This enables man-in-the-middle SSL stripping, Cross-Site Scripting (XSS), and Clickjacking attacks against client browsers."
    },
    {
        "doc_id": "VULN-TECH-LEAKAGE",
        "category": "OWASP_TOP_10",
        "title": "OWASP A06:2021 - Vulnerable and Outdated Components (Version Leakage)",
        "tactic": "Discovery",
        "content": "Broadcasting exact server software names and versions via 'Server' or 'X-Powered-By' HTTP headers provides attackers with precise reconnaissance data. This facilitates automated targeting of known exploits against specific outdated software stacks."
    },

    # Remediation Guides
    {
        "doc_id": "REM-SSH-HARDENING",
        "category": "REMEDIATION_GUIDE",
        "title": "Remediation Guide: OpenSSH Hardening & Access Control",
        "tactic": "Mitigation",
        "content": "1. Upgrade OpenSSH immediately to version 9.8p1 or newer. 2. Configure SSHd (`/etc/ssh/sshd_config`) to disable root login (`PermitRootLogin no`) and enforce public-key authentication (`PasswordAuthentication no`). 3. Restrict TCP port 22 strictly to trusted corporate IP whitelists or VPN gateways using iptables/ufw (`ufw allow from <TRUSTED_IP> to any port 22 proto tcp`)."
    },
    {
        "doc_id": "REM-WEB-HEADERS",
        "category": "REMEDIATION_GUIDE",
        "title": "Remediation Guide: HTTP Security Header Configuration",
        "tactic": "Mitigation",
        "content": "In Nginx (`/etc/nginx/nginx.conf`), add: `add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;` and `add_header Content-Security-Policy \"default-src 'self';\" always;`. In Apache (`httpd.conf`), use `Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"`. Also suppress version leakage by setting `server_tokens off;` in Nginx or `ServerTokens Prod` in Apache."
    },
    {
        "doc_id": "REM-REDIS-SECURE",
        "category": "REMEDIATION_GUIDE",
        "title": "Remediation Guide: Securing Exposed Redis Services",
        "tactic": "Mitigation",
        "content": "1. Bind Redis strictly to localhost (`bind 127.0.0.1 -::1` in `redis.conf`) or private internal interfaces. 2. Enable strong authentication using `requirepass <STRONG_PASSWORD>`. 3. Block external access to TCP port 6379 at the perimeter firewall."
    }
]
