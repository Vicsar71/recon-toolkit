from __future__ import annotations
import re
import httpx
from ..models import HttpFingerprint, PortResult

HTTP_PORTS = {80, 8080, 8000, 8888, 3000, 5000, 8008}
HTTPS_PORTS = {443, 8443, 4443}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

_COOKIE_HINTS: dict[str, str] = {
    "phpsessid": "PHP",
    "asp.net_sessionid": "ASP.NET",
    "aspsessionid": "ASP.NET",
    "jsessionid": "Java",
    "laravel_session": "Laravel",
    "wordpress_": "WordPress",
    "ci_session": "CodeIgniter",
    "csrftoken": "Django",
}


def _extract_title(html: str) -> str:
    m = _TITLE_RE.search(html)
    return " ".join(m.group(1).strip().split()) if m else ""


def _detect_technologies(headers: httpx.Headers, cookies: httpx.Cookies) -> list[str]:
    techs: set[str] = set()

    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        techs.add(powered_by.split("/")[0].strip())

    cookie_keys_lower = [k.lower() for k in cookies.keys()]
    for hint, tech in _COOKIE_HINTS.items():
        if any(hint in k for k in cookie_keys_lower):
            techs.add(tech)

    return sorted(techs)


def _scheme_for_port(port: int, service: str) -> str | None:
    svc = service.lower()
    if port in HTTPS_PORTS or svc == "https" or svc == "https-alt":
        return "https"
    if port in HTTP_PORTS or "http" in svc:
        return "http"
    return None


def fingerprint_port(host: str, port: int, service: str = "") -> HttpFingerprint | None:
    scheme = _scheme_for_port(port, service)
    if scheme is None:
        return None

    url = f"{scheme}://{host}:{port}"

    try:
        with httpx.Client(verify=False, timeout=5.0, follow_redirects=True) as client:
            resp = client.get(url)
            title = _extract_title(resp.text)
            server = resp.headers.get("server", "")
            powered_by = resp.headers.get("x-powered-by", "")
            technologies = _detect_technologies(resp.headers, resp.cookies)

            robots = ""
            try:
                rb = client.get(f"{url}/robots.txt")
                if rb.status_code == 200 and "plain" in rb.headers.get("content-type", ""):
                    robots = rb.text[:500]
            except Exception:
                pass

            return HttpFingerprint(
                url=url,
                status_code=resp.status_code,
                title=title,
                server=server,
                powered_by=powered_by,
                technologies=technologies,
                robots_txt=robots,
            )
    except Exception as exc:
        return HttpFingerprint(url=url, error=str(exc)[:120])


def fingerprint_web_ports(host: str, open_ports: list[PortResult]) -> list[HttpFingerprint]:
    results: list[HttpFingerprint] = []
    for port_result in open_ports:
        fp = fingerprint_port(host, port_result.port, port_result.service)
        if fp is not None:
            results.append(fp)
    return results
