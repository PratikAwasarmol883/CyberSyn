from fastapi import APIRouter, HTTPException
from helper import normalize_subdomain, is_real_subdomain, dns_resolves
import dns.resolver

domainRouter = APIRouter(prefix="/domain-discovery")


def dns_wildcard_detect(domain):
    """
    Checks whether wildcard DNS is enabled for *.domain
    """
    test_sub = "random-test-wildcard-check." + domain
    return dns_resolves(test_sub)


def dns_based_discovery(domain, wordlist=None):
    """
    Dynamic DNS brute-force discovery.
    """
    if wordlist is None:
        wordlist = [
            "www", "mail", "smtp", "imap", "pop", "web", "api",
            "secure", "portal", "login", "mta-sts", "admin"
        ]

    wildcard = dns_wildcard_detect(domain)
    candidates = [f"{w}.{domain}" for w in wordlist]
    candidates = list(set(candidates))

    # Normalize formatting
    candidates = [
        normalize_subdomain(c) for c in candidates
        if normalize_subdomain(c)
    ]

    valid_subdomains = []
    for sub in candidates:
        if is_real_subdomain(sub, domain):
            # If wildcard is ON → deeper validation already happens in is_real_subdomain()
            valid_subdomains.append(sub)

    return {
        "domain": domain,
        "method": "dns_validation",
        "wildcard_detected": wildcard,
        "total_found": len(valid_subdomains),
        "subdomains": sorted(set(valid_subdomains))
    }


@domainRouter.get("")
def domain_discovery(domain: str):
    """
    Final API endpoint.
    """
    try:
        result = dns_based_discovery(domain)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
