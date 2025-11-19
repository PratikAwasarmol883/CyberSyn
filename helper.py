import dns.resolver
import dns.exception
import re


def dns_resolves(hostname):
    """
    Returns True if the hostname resolves to A, AAA or CNAME.
    """
    try:
        for t in ["A", "AAAA", "CNAME"]:
            dns.resolver.resolve(hostname, t, lifetime=1)
            return True
        return False
    except dns.exception.DNSException:
        return False


def normalize_subdomain(subdomain):
    """
    Cleans and normalizes strings like '*.mail.example.com'
    """
    if not subdomain:
        return None

    subdomain = subdomain.strip().lower()
    subdomain = subdomain.replace("*.", "")

    if not re.match(r"^[a-z0-9.-]+$", subdomain):
        return None

    return subdomain


def looks_suspicious(subdomain):
    """
    Filters out unlikely or random-looking subdomains.
    """
    bad_patterns = [
        r"[0-9]{5,}",
        r"--",
        r"@",
        r"[^a-z0-9.-]",
    ]
    for p in bad_patterns:
        if re.search(p, subdomain):
            return True
    return False


def is_real_subdomain(subdomain, root_domain):
    """
    Validates:
    - must end with domain
    - must not look suspicious
    - must resolve
    """
    if not subdomain.endswith(root_domain):
        return False

    if looks_suspicious(subdomain):
        return False

    return dns_resolves(subdomain)
