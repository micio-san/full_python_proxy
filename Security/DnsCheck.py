from logConf import logger
#Decide whether a user-supplied URL is safe and allowed to fetch.
#splits url
from urllib.parse import urlparse, unquote
#work with network connections
import socket
#check what kind of IP, standard-library module
import ipaddress

#region security rules
ALLOWED_HOSTNAMES = {"example.com", "api.myserver.com"}
ALLOWED_PORTS = {80, 443, 8080}
ALLOWED_NETWORKS = [ipaddress.ip_network("203.0.113.0/24")]

def is_private_ip(ip):
    addy = ipaddress.ip_address(ip)
    return addy.is_private or addy.is_loopback or addy.is_link_local

def is_allowed_target(target_url):
    if target_url == "favicon.ico":
        return True
    u=urlparse(unquote(target_url))
    logger.info(f"{target_url} || {u.scheme} || {u.hostname} || {u.port} || {u.path}")
    #gives an object with: u.scheme → "https" || u.hostname → "example.com" || u.port → None || u.path → "/test"
    if u.scheme not in ("http", "https"):
        logger.error(f"{u.scheme} Scheme failure")
        return False
    if not u.hostname or u.hostname not in ALLOWED_HOSTNAMES:
        logger.error(f"{u.hostname} Hostname fail")
        return False
    #DNS resolution + IP checks to prevent the proxy from connecting to private/internal addresses (classic SSRF protection)
    try:
        infos = socket.getaddrinfo(u.hostname, None) 
        logger.info(infos)
        #(family, socktype, proto, canonname, sockaddr)
        #AddressFamily.AF_INET: 2>,'','','',<Sockaddr>
        for family, _, _, _, sockaddr in infos: 
            ip = sockaddr[0] 
            if is_private_ip(ip): 
               logger.info(ip)
               return False
    except Exception:
        logger.error(str(Exception))
        return False
    if u.port and int(u.port) not in ALLOWED_PORTS:
        logger.error(f"{u.port} error porta or porta not in ALLOWED_PORTS")
        return False
    logger.info(f"{target_url} OK")
    return True
    