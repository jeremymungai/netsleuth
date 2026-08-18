"""Well-known port → service name mapping (offline, extendable via rules)."""

from __future__ import annotations

SERVICES: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    37: "time", 43: "whois", 49: "tacacs", 53: "dns", 67: "dhcp-server",
    68: "dhcp-client", 69: "tftp", 79: "finger", 80: "http", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmptrap", 179: "bgp", 389: "ldap", 427: "svrloc", 443: "https",
    445: "microsoft-ds", 465: "smtps", 500: "isakmp", 512: "rexec",
    513: "rlogin", 514: "syslog", 515: "printer", 548: "afp", 554: "rtsp",
    587: "submission", 591: "http-alt", 593: "http-rpc-epmap", 623: "ipmi",
    636: "ldaps", 644: "sane", 771: "rtelnet", 873: "rsync", 902: "vmware-auth",
    993: "imaps", 995: "pop3s", 1080: "socks", 1099: "jmx", 1194: "openvpn",
    1214: "kazaa", 1241: "nessus", 1293: "ipsec", 1433: "mssql",
    1521: "oracle", 1723: "pptp", 1812: "radius", 1900: "upnp",
    2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl", 2121: "ftp-proxy",
    2181: "zookeeper", 2375: "docker", 2376: "docker-tls", 2404: "iec-104",
    2483: "oracle-tcp", 2484: "oracle-ssl", 3000: "node-dev",
    3128: "squid", 3260: "iscsi", 3306: "mysql", 3389: "rdp", 3478: "stun",
    3690: "svn", 4321: "rwhois", 4444: "metasploit", 4500: "ipsec-nat",
    4567: "sinema", 4840: "opc-ua", 5000: "upnp-alt", 5001: "synology",
    5060: "sip", 5222: "xmpp", 5353: "mdns", 5357: "wsd", 5432: "postgresql",
    5555: "adb", 5601: "kafka-manager",
    5672: "amqp", 5666: "nrpe", 5800: "vnc-http", 5900: "vnc", 5938: "teamviewer",
    5984: "couchdb", 6000: "x11", 6001: "x11", 6379: "redis", 6443: "kubernetes-api",
    6660: "irc-alt", 6667: "irc", 7001: "weblogic", 7070: "http-alt",
    8000: "http-alt", 8008: "http-alt", 8009: "ajp13", 8010: "xmpp",
    8080: "http-proxy", 8081: "http-alt", 8443: "https-alt", 8500: "consul",
    8686: "jmx-alt", 8888: "http-alt", 9000: "sonar", 9001: "tor-orport",
    9080: "websphere", 9100: "printer-jetdirect", 9200: "elasticsearch",
    9418: "git", 9999: "abyss", 10000: "webmin", 11211: "memcached",
    12345: "netbus", 27017: "mongodb", 31337: "elite", 50050: "java-rmi",
    55553: "metasploit-http", 61613: "smpp",
}

# Ports where cleartext protocols habitually run even when nonstandard
CLEARTEXT_HTTP_PORTS = {80, 591, 593, 7070, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9080, 9999, 10000}


def service_name(port: int, proto: str = "tcp") -> str:
    name = SERVICES.get(port, "")
    if not name:
        return ""
    if proto == "udp" and port in (53, 67, 68, 69, 123, 137, 138, 161, 500, 514, 1900, 5353, 3478):
        return name
    if proto == "tcp" and port in (53, 67, 68, 69, 123, 137, 138, 161, 500, 514, 1900, 5353, 3478):
        return ""      # predominantly-UDP service seen on TCP — don't guess
    return name
