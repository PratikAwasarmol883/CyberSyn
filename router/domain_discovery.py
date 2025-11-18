from fastapi import APIRouter
import subprocess
from helper import is_valid_domain

domainRouter = APIRouter(prefix="/domain-discovery")

@domainRouter.get("")
def domain_discovery(domain: str):
    file_name = f"domain_{domain}.txt"
    cmd = ["subfinder", "-d", domain, "-o", file_name]

    subprocess.run(cmd)

    with open(file_name) as f:
        subs = f.read().splitlines()

    valid_subdomain = [sub for sub in subs if is_valid_domain(sub)]

    return {
        "domain": domain,
        "total_found": len(subs),
        "valid_subdomains": len(valid_subdomain),
        "subdomains": valid_subdomain
    }
