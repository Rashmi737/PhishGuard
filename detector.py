"""
PhishGuard – Rule-based phishing URL detection engine.

IMPORTANT SECURITY PRINCIPLE
----------------------------
This module performs *static, heuristic-only* analysis. It NEVER visits,
fetches, renders or executes the submitted URL in any way. The URL string
is only parsed with the standard-library `urllib.parse` module, which does
not perform any network activity.

How scoring works
-----------------
Each check that fires adds a weighted number of points. Points are summed
and clamped to the inclusive range 0-100. The final score is split into:

    0-29   -> Low Risk
    30-69  -> Medium Risk
    70-100 -> High Risk

This is NOT proof that a website is safe or malicious. Heuristic analysis
can produce BOTH false positives (a legitimate URL flagged as suspicious)
and false negatives (a convincing phishing URL scored as low risk).
"""

import ipaddress
import re
from urllib.parse import urlparse, unquote

MAX_URL_LENGTH = 2048

# Ports that are completely normal for websites. Anything else adds a small
# risk weight (phishing kits sometimes run on odd ports like 8080/4443).
_USUAL_PORTS = {80, 443, 8080, 8443}

# Well-known URL shortening services. Shorteners hide the real destination,
# which is why phishers abuse them.
_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "tiny.cc", "cutt.ly", "rb.gy", "rebrand.ly", "t.ly", "shorturl.at",
    "v.gd", "qr.ae", "s.id", "bl.ink", "ouo.io", "tiny.one",
}

# Keywords that frequently appear in phishing URLs. A keyword alone is never
# enough to call a URL "phishing" — it only adds a small weighted amount.
_SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "account", "password", "secure",
    "signin", "confirm", "banking", "wallet", "suspended", "billing",
    "unlock", "webscr", "validation",
]

# Free / heavily abused TLDs. Weighted lightly on purpose — many legitimate
# sites use them, but they are over-represented in phishing campaigns.
_RISKY_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "work", "club", "date",
    "racing", "kim", "zip", "mov",
}

# Common two-part public suffixes, used only for smarter subdomain counting.
_TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "com.br", "co.jp", "com.mx", "co.in", "ac.in", "edu.in", "gov.in",
    "com.sg", "com.tr", "com.cn",
}

# Brands commonly impersonated with digit substitution (e.g. "paypa1.com",
# "g00gle.com"). The host is normalised digit -> letter and re-checked.
_BRAND_LOOKALIKES = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "netflix", "instagram", "whatsapp", "linkedin", "icloud", "outlook",
    "chase", "wellsfargo", "bankofamerica", "hdfcbank", "netflix",
]


def _normalize_url(raw):
    """Trim, add a scheme if missing and reject dangerous input."""
    if raw is None:
        return None, "URL cannot be empty."
    if not isinstance(raw, str):
        return None, "URL must be text."

    url = raw.strip()

    if not url:
        return None, "Please enter a URL to scan."
    if len(url) > MAX_URL_LENGTH:
        return None, f"URL is too long (maximum {MAX_URL_LENGTH} characters)."

    # Reject whitespace and control characters anywhere in the input. A real
    # URL never contains them and they are a classic injection vector.
    if re.search(r"[\s\x00-\x1f\x7f]", url):
        return None, "URL cannot contain spaces or control characters."

    # Add https:// automatically when the user types "example.com".
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://", url)
    if scheme_match:
        scheme = scheme_match.group(1).lower()
        if scheme not in ("http", "https"):
            return None, f"Only http:// and https:// URLs are supported (got '{scheme}://')."
    else:
        url = "https://" + url

    return url, None


def _split_registered_domain(hostname):
    """
    Return (registered_domain, subdomain_label_count).

    Example: "a.b.example.co.uk" -> ("example.co.uk", 2)
    Works on a best-effort basis without a full public-suffix list.
    """
    labels = hostname.split(".")
    if len(labels) < 2:
        return hostname, 0

    last_two = ".".join(labels[-2:])
    if last_two in _TWO_PART_SUFFIXES and len(labels) >= 3:
        suffix_len = 3
    else:
        suffix_len = 2

    registered = ".".join(labels[-suffix_len:])
    sub_count = len(labels) - suffix_len
    return registered, max(0, sub_count)


def _is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def _looks_like_brand_lookalike(hostname):
    """
    Detect digit-for-letter substitution used for impersonation,
    e.g. "paypa1.com" -> looks like "paypal.com".
    """
    table = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "@": "a"})
    normalised = hostname.translate(table)
    if normalised == hostname:
        return False
    for brand in _BRAND_LOOKALIKES:
        if brand in normalised and brand not in hostname:
            return True
    return False


def analyze_url(raw_url):
    """
    Analyse a URL and return a dict result:

        {
          "success": bool,
          "error": str | None,
          "url": original input,
          "normalized_url": canonical URL analysed,
          "domain": hostname,
          "https": bool,
          "score": int (0-100),
          "category": "Low Risk" | "Medium Risk" | "High Risk",
          "risk_level": "low" | "medium" | "high",
          "indicators": [{"label", "points", "detail"}, ...],
          "warnings": [flat strings for backwards compatibility],
          "explanation": str,
          "recommendation": str,
        }
    """
    result = {
        "success": False,
        "error": None,
        "url": raw_url,
        "normalized_url": None,
        "domain": None,
        "https": False,
        "score": 0,
        "category": "Low Risk",
        "risk_level": "low",
        "indicators": [],
        "warnings": [],
        "explanation": "",
        "recommendation": "",
    }

    normalized, err = _normalize_url(raw_url)
    if err:
        result["error"] = err
        return result

    try:
        parsed = urlparse(normalized)
    except Exception:
        result["error"] = "That does not look like a valid URL. Please check and try again."
        return result

    # urlparse never raises for hostile strings, but strict rules below
    # guarantee the pieces we rely on are sound.
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        result["error"] = "Only http:// and https:// URLs are supported."
        return result

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        result["error"] = "Missing domain name. Example: https://example.com"
        return result

    try:
        parsed.port  # raises ValueError for an invalid/out-of-range port
    except ValueError:
        result["error"] = "The port number in this URL is invalid."
        return result

    # Remove trailing dot and decode any percent-encoding for analysis only.
    hostname = hostname.rstrip(".")
    decoded_path = unquote(parsed.path or "")

    indicators = []  # list of (label, points, detail)

    def add(label, points, detail):
        indicators.append({"label": label, "points": points, "detail": detail})

    # ------------------------------------------------------------------
    # 1. Transport security — absence of HTTPS is a *signal*, not proof.
    # ------------------------------------------------------------------
    using_https = scheme == "https"
    if not using_https:
        add("No HTTPS encryption", 15,
            "The page is served over plain HTTP, so data can be intercepted or modified in transit.")

    # ------------------------------------------------------------------
    # 2. URL length — phishing URLs are often padded to look official.
    # ------------------------------------------------------------------
    url_len = len(normalized)
    if url_len > 75:
        add("Very long URL", 15, f"The URL is {url_len} characters long (over 75).")
    elif url_len > 54:
        add("Long URL", 8, f"The URL is {url_len} characters long (over 54).")

    # ------------------------------------------------------------------
    # 3. IP address instead of a domain name.
    # ------------------------------------------------------------------
    host_is_ip = _is_ip_address(hostname)
    if host_is_ip:
        add("IP address instead of domain", 30,
            "The host is a raw IP address — phishing kits frequently use IPs to dodge blocklists.")

    # Subdomain counting only makes sense for real domain names, not IPs.
    if host_is_ip:
        registered_domain, sub_count = hostname, 0
    else:
        registered_domain, sub_count = _split_registered_domain(hostname)

    # ------------------------------------------------------------------
    # 4. Excessive subdomains (e.g. login.secure.example.com).
    # ------------------------------------------------------------------
    if sub_count >= 4:
        add("Excessive subdomains", 15, f"{sub_count} subdomain levels detected.")
    elif sub_count == 3:
        add("Many subdomains", 10, "3 subdomain levels detected.")
    elif sub_count == 2:
        add("Multiple subdomains", 5, "2 subdomain levels detected.")

    # ------------------------------------------------------------------
    # 5. Suspicious keywords — weighted individually, capped overall.
    # ------------------------------------------------------------------
    haystack = f"{hostname} {decoded_path} {parsed.query or ''}".lower()
    hits = sorted({kw for kw in _SUSPICIOUS_KEYWORDS if kw in haystack})
    if hits:
        keyword_points = min(18, 6 * len(hits))
        shown = ", ".join(hits[:6])
        add("Suspicious keywords", keyword_points, f"Contains: {shown}.")

    # ------------------------------------------------------------------
    # 6. "@" symbol — everything before "@" is ignored by browsers and
    #    abused to disguise the real destination.
    # ------------------------------------------------------------------
    if "@" in normalized:
        add("'@' symbol in URL", 25,
            "The '@' hides the real destination — the text before it is ignored by browsers.")

    # ------------------------------------------------------------------
    # 7. Unusual number of hyphens in the host.
    # ------------------------------------------------------------------
    hyphen_count = hostname.count("-")
    if hyphen_count >= 4:
        add("Many hyphens in domain", 15, f"{hyphen_count} hyphens found in the hostname.")
    elif hyphen_count >= 2:
        add("Multiple hyphens in domain", 8, f"{hyphen_count} hyphens found in the hostname.")

    # ------------------------------------------------------------------
    # 8. URL shortening services — they mask the true destination.
    # ------------------------------------------------------------------
    if hostname in _SHORTENERS or any(hostname.endswith("." + s) for s in _SHORTENERS):
        add("URL shortener", 12,
            f"'{hostname}' hides the real destination behind a redirect.")

    # ------------------------------------------------------------------
    # 9. Suspicious domain patterns (structural, not just keywords).
    # ------------------------------------------------------------------
    if "xn--" in hostname:
        add("Punycode / internationalized domain", 20,
            "Uses 'xn--' encoding — often abused for homograph attacks that mimic real domains.")

    if _looks_like_brand_lookalike(hostname):
        add("Brand lookalike (digit substitution)", 18,
            f"'{hostname}' resembles a well-known brand written with digits (e.g. paypa1, g00gle).")

    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    if tld in _RISKY_TLDS:
        add("Commonly abused TLD", 6, f"The '.{tld}' TLD is disproportionately used in phishing campaigns.")

    if parsed.port is not None and parsed.port not in _USUAL_PORTS:
        add("Unusual port", 5, f"Port {parsed.port} is not a standard web port.")

    # ------------------------------------------------------------------
    # Final scoring — clamp to 0-100.
    # ------------------------------------------------------------------
    score = min(100, sum(i["points"] for i in indicators))
    if score < 30:
        category, level = "Low Risk", "low"
    elif score < 70:
        category, level = "Medium Risk", "medium"
    else:
        category, level = "High Risk", "high"

    if score == 0:
        explanation = (
            "No suspicious characteristics were detected by the rule-based engine. "
            "This does NOT guarantee the site is safe — the URL was never visited or loaded."
        )
        recommendation = (
            "The URL shows no strong heuristic signals. Still check the domain name manually, "
            "look for HTTPS and a valid padlock, and never enter credentials unless you are sure "
            "who owns the site."
        )
    else:
        names = ", ".join(i["label"] for i in indicators)
        explanation = (
            f"This URL triggered {len(indicators)} heuristic indicator(s): {names}. "
            f"The combined weighted score is {score}/100 ({category}). "
            "HTTPS alone is never treated as proof of safety; the score reflects structure, "
            "content keywords, and domain reputation signals only."
        )
        if level == "low":
            recommendation = (
                "Only minor signals were found. Stay alert: verify the exact domain spelling, "
                "prefer HTTPS, and never share passwords or one-time codes from an unsolicited link."
            )
        elif level == "medium":
            recommendation = (
                "Proceed with caution. Do not enter credentials or payment details. If this link "
                "arrived by email or message, confirm it with the supposed sender through an "
                "official channel before opening it."
            )
        else:
            recommendation = (
                "Do NOT open this link and do NOT enter any information. Treat it as phishing: "
                "close the page, do not download anything, report the message to your email/IT "
                "provider, and delete it. If you already entered credentials, change your password "
                "immediately and enable two-factor authentication."
            )

    # Always disclose the heuristic nature of the check.
    explanation += (
        " Heuristic detection can produce false positives and false negatives — "
        "use it as one signal among many, not as a final verdict."
    )

    result.update({
        "success": True,
        "error": None,
        "normalized_url": normalized,
        "domain": hostname,
        "https": using_https,
        "score": score,
        "category": category,
        "risk_level": level,
        "indicators": indicators,
        "warnings": [i["label"] for i in indicators],
        "explanation": explanation,
        "recommendation": recommendation,
    })
    return result
