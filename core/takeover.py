"""Subdomain Takeover Detection Module - SubHunter v5.0

Checks for subdomain takeover vulnerabilities by analyzing CNAME records
and matching against known vulnerable service fingerprints.
"""
import asyncio
import aiodns
import httpx
from typing import List, Dict, Set
from utils.display import Colors

# Fingerprints for common services
# Format: 'cname_substring': ['response_fingerprint']
TAKEOVER_SIGNATURES = {
    "github.io": ["There isn't a GitHub Pages site here", "404 There isn't a GitHub Pages site here"],
    "herokuapp.com": ["No such app", "There's nothing here, yet"],
    "amazonaws.com": ["NoSuchBucket", "The specified bucket does not exist"],
    "azurewebsites.net": ["404 Web Site not found"],
    "cloudapp.net": ["404 Web Site not found"],
    "visualstudio.com": ["404 Web Site not found"],
    "myshopify.com": ["Sorry, this shop is currently unavailable"],
    "wordpress.com": ["Do you want to register", "doesn't exist"],
    "tumblr.com": ["There's nothing here", "Whatever you were looking for doesn't currently exist at this address"],
    "cargo.site": ["404 Not Found"],
    "helprace.com": ["Alias not configured"],
    "desk.com": ["Please try again or try Desk.com"],
    "teamwork.com": ["Oops - We didn't find your site"],
    "helpscoutdocs.com": ["No settings were found for this company"],
    "ghost.io": ["The thing you were looking for is no longer here"],
    "surge.sh": ["project not found"],
    "pantheon.io": ["404 error unknown site"],
    "readme.io": ["Project doesnt exist... yet!"],
    "fastly.net": ["Fastly error: unknown domain"],
    "smartjobboard.com": ["This job board website is either expired or its domain name is invalid"],
    "uservoice.com": ["This UserVoice subdomain is currently available"],
    "zendesk.com": ["Help Center Closed"],
}

# Concurrency caps: DNS lookups are cheap and fast, HTTP verification is not.
DNS_CONCURRENCY = 100
VERIFY_CONCURRENCY = 20


def match_takeover_signature(cname_target: str) -> Dict:
    """Match a CNAME target against known takeover fingerprints.

    Returns the candidate dict, or None if no service signature matches.
    """
    if not cname_target:
        return None
    for sig, fingerprints in TAKEOVER_SIGNATURES.items():
        if sig in cname_target:
            return {"service": sig, "fingerprints": fingerprints}
    return None


async def check_takeover(domain: str, subdomains: List[str], resolver: aiodns.DNSResolver, quiet: bool = False) -> List[Dict]:
    """
    Check for subdomain takeover vulnerabilities.
    Returns a list of verified vulnerable subdomains with details.
    """
    results = []

    if not quiet:
        print(f"\n{Colors.CYAN}[*] Phase 6: Checking for Subdomain Takeovers{Colors.RESET}")

    # Phase 1: resolve CNAMEs concurrently (was sequential before, which made
    # large scans crawl: one DNS round-trip per subdomain, one at a time).
    dns_sem = asyncio.Semaphore(DNS_CONCURRENCY)

    async def check_cname(sub: str):
        async with dns_sem:
            try:
                # A pure A record implies no CNAME, but takeover vectors need a
                # CNAME pointing at a deleted resource, so we only check CNAME.
                result = await resolver.query(sub, 'CNAME')
                cname_target = result.cname
            except Exception:
                return None  # No CNAME or resolution failed
            match = match_takeover_signature(cname_target)
            if match:
                return {
                    "subdomain": sub,
                    "cname": cname_target,
                    "service": match["service"],
                    "fingerprints": match["fingerprints"],
                }
            return None

    candidates = [c for c in
                  await asyncio.gather(*[check_cname(s) for s in subdomains],
                                       return_exceptions=True)
                  if isinstance(c, dict)]

    # Phase 2: verify candidates with HTTP, concurrently
    if candidates and not quiet:
        print(f"  {Colors.YELLOW}[!]{Colors.RESET}  Found {len(candidates)} potential CNAME targets. Verifying...")

    verified = []
    verify_sem = asyncio.Semaphore(VERIFY_CONCURRENCY)

    async def verify_candidate(client: httpx.AsyncClient, candidate: Dict):
        async with verify_sem:
            try:
                url = f"http://{candidate['subdomain']}"
                response = await client.get(url)
                content = response.text

                for fp in candidate['fingerprints']:
                    if fp in content:
                        candidate['verified'] = True
                        return candidate
            except Exception:
                pass
            return None

    if candidates:
        async with httpx.AsyncClient(verify=False, timeout=5) as client:
            found = await asyncio.gather(
                *[verify_candidate(client, c) for c in candidates],
                return_exceptions=True)
            verified = [c for c in found if isinstance(c, dict)]
            if not quiet:
                for c in verified:
                    print(f"  {Colors.RED}[!] VULNERABLE: {c['subdomain']} -> {c['service']}{Colors.RESET}")

    return verified
