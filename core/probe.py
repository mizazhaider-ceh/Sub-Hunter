"""
HTTP probing and technology detection - SubHunter v5.0

Enhanced with:
- Cloud provider detection
- CNAME tracking
- Improved header analysis
"""
import asyncio
import re
import socket
import time
from typing import Set, List, Optional, Dict
import httpx
from utils.display import Colors
from utils.config import TECH_SIGNATURES
from core.cloud import detect_cloud_provider, get_cloud_color


async def resolve_ip(subdomain: str) -> str:
    """Resolve subdomain to IP address."""
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, socket.gethostbyname, subdomain)
        return result
    except Exception:
        return ""


def cookie_is_httponly(cookie) -> bool:
    """Check the HttpOnly flag on a cookie object.

    http.cookiejar stores HttpOnly as a non-standard attribute; str(cookie)
    only gives the name=value pair, so a substring check on the string never
    sees the flag (it was always False before this helper).
    """
    try:
        return bool(cookie.has_nonstandard_attr('HttpOnly'))
    except Exception:
        return False


DEFAULT_UA = 'Mozilla/5.0 (SubHunter/5.0)'


async def probe_http(
    subdomain: str,
    timeout: float = 5.0,
    cname: str = None,
    client: "httpx.AsyncClient" = None,
) -> Dict:
    """
    Probe HTTP/HTTPS for a subdomain with detailed info.

    Args:
        subdomain: Target subdomain to probe
        timeout: Request timeout
        cname: Pre-resolved CNAME if available
        client: Optional shared httpx.AsyncClient (created per call if omitted)
    """

    # First resolve IP
    ip = await resolve_ip(subdomain)

    result = {
        "subdomain": subdomain,
        "ip": ip,
        "cname": cname,
        "alive": False,
        "url": None,
        "final_url": None,
        "status": None,
        "title": None,
        "tech": [],
        "server": None,
        "content_type": None,
        "content_length": 0,
        "response_time": 0,
        "headers": {},
        "redirect_chain": [],
        "cookies": [],
        "meta_description": None,
        "protocol": None,
        "cloud_provider": None,
    }

    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=timeout, verify=False,
                                   follow_redirects=True,
                                   headers={'User-Agent': DEFAULT_UA})
    try:
        for protocol in ["https", "http"]:
            url = f"{protocol}://{subdomain}"
            try:
                start_time = time.time()
                response = await client.get(url)
                end_time = time.time()

                result["alive"] = True
                result["url"] = url
                result["final_url"] = str(response.url)
                result["status"] = response.status_code
                result["protocol"] = protocol.upper()
                result["response_time"] = round((end_time - start_time) * 1000)  # ms

                # Headers
                result["server"] = response.headers.get("server", "")
                result["content_type"] = response.headers.get("content-type", "")
                result["content_length"] = len(response.content)

                # Store important headers
                important_headers = [
                    "x-powered-by", "x-frame-options", "x-xss-protection",
                    "content-security-policy", "strict-transport-security",
                    "x-content-type-options", "access-control-allow-origin",
                    "x-amz-cf-id", "x-amz-request-id",  # AWS
                    "x-ms-request-id",  # Azure
                    "cf-ray", "cf-cache-status",  # Cloudflare
                    "x-vercel-id",  # Vercel
                    "x-netlify-request-id",  # Netlify
                ]
                for h in important_headers:
                    if h in response.headers:
                        result["headers"][h] = response.headers[h]

                # Cookies
                for cookie in response.cookies.jar:
                    result["cookies"].append({
                        "name": cookie.name,
                        "secure": cookie.secure,
                        "httponly": cookie_is_httponly(cookie)
                    })

                # Redirect chain
                if response.history:
                    for r in response.history:
                        result["redirect_chain"].append({
                            "url": str(r.url),
                            "status": r.status_code
                        })

                # Extract title
                title_match = re.search(r"<title[^>]*>([^<]+)</title>", response.text, re.IGNORECASE)
                if title_match:
                    result["title"] = title_match.group(1).strip()[:100]

                # Extract meta description
                desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']+)["\']', response.text, re.IGNORECASE)
                if desc_match:
                    result["meta_description"] = desc_match.group(1).strip()[:200]

                # Detect technologies
                content = response.text.lower() + str(response.headers).lower()
                for tech, patterns in TECH_SIGNATURES.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            if tech not in result["tech"]:
                                result["tech"].append(tech)
                            break

                # Detect cloud provider
                result["cloud_provider"] = detect_cloud_provider(
                    ip=ip,
                    cname=cname,
                    headers=dict(response.headers)
                )

                return result
            except Exception:
                continue
    finally:
        if own_client:
            await client.aclose()

    # Even if not alive, try to detect cloud from CNAME/IP
    if cname or ip:
        result["cloud_provider"] = detect_cloud_provider(ip=ip, cname=cname)

    return result


async def probe_all(
    subdomains: Set[str],
    concurrency: int = 50,
    quiet: bool = False,
    dns_results: Dict = None
) -> List[Dict]:
    """
    Probe all subdomains.
    
    Args:
        subdomains: Set of subdomains to probe
        concurrency: Concurrent probes
        quiet: Suppress output
        dns_results: Dict mapping subdomain -> DNSResult for CNAME info
    """
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    dns_results = dns_results or {}

    # One shared client for every probe: connection reuse instead of a new
    # TLS handshake per subdomain (was the dominant cost of phase 3).
    async with httpx.AsyncClient(timeout=10.0, verify=False,
                                 follow_redirects=True,
                                 headers={'User-Agent': DEFAULT_UA}) as client:
        async def probe(sub: str):
            async with semaphore:
                # Get CNAME if we have DNS info
                cname = None
                if sub in dns_results:
                    dns_info = dns_results[sub]
                    if hasattr(dns_info, 'cname'):
                        cname = dns_info.cname
                    elif isinstance(dns_info, dict):
                        cname = dns_info.get('cname')
    
                result = await probe_http(sub, cname=cname, client=client)
                results.append(result)
    
                if result["alive"] and not quiet:
                    status_color = Colors.GREEN if result["status"] == 200 else Colors.YELLOW
                    tech_str = f" [{', '.join(result['tech'][:3])}]" if result["tech"] else ""
                    ip_str = f" ({result['ip']})" if result['ip'] else ""
    
                    # Cloud provider indicator
                    cloud_str = ""
                    if result.get("cloud_provider"):
                        cloud_color = get_cloud_color(result["cloud_provider"])
                        cloud_str = f" {cloud_color}☁ {result['cloud_provider']}{Colors.RESET}"
    
                    print(f"  {Colors.GREEN}●{Colors.RESET} [{status_color}{result['status']}{Colors.RESET}] {result['url']}{Colors.DIM}{ip_str}{tech_str}{Colors.RESET}{cloud_str}")
    
        tasks = [probe(sub) for sub in subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)
        return results
