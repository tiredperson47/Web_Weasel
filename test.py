from urllib.parse import urlparse
import re

# Simple IPv4 matcher
ipv4_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

def parse_host(input_str):
    """
    Takes either:
        - raw host (example.com)
        - URL (https://example.com/path)
    Returns dict with:
        - base_domain
        - subdomain
        - type
    """
    # Normalize input: parse as URL if it has a scheme
    if "://" in input_str:
        parsed = urlparse(input_str)
        host = parsed.hostname  # automatically strips scheme, path, port
        base_path = parsed.path.rstrip("/") or None
    else:
        if "/" in input_str:
            host, path = input_str.split("/", 1)
            base_path = "/" + path.rstrip("/") if path else None
        else:
            host = input_str
            base_path = None

    if host is None:
        raise ValueError(f"Invalid host in input: {input_str}")

    # Now we safely have only the hostnam
    parts = host.split('.')

    # -------------------------------
    # Case 1: Pure IPv4
    # -------------------------------
    if ipv4_re.match(host):
        return {
            "base_domain": host,
            "full_host": host,
            "base_path": base_path,
            "has_subdomain": False
        }

    # -------------------------------
    # Case 2: IPv4 WITH a subdomain
    # Example: s3.monitor.192.168.1.10
    # -------------------------------
    if len(parts) > 4 and ipv4_re.match(".".join(parts[-4:])):
        ip = ".".join(parts[-4:])
        sub = ".".join(parts[:-4]) + f".{ip}"
        return {
            "base_domain": ip,
            "full_host": sub,
            "base_path": base_path,
            "has_subdomain": True
        }

    # -------------------------------
    # Case 3: Domain with subdomains
    # -------------------------------
    if len(parts) >= 3:
        base = ".".join(parts[-2:])
        return {
            "base_domain": base,
            "full_host": ".".join(parts[:-2]) + f".{base}",
            "base_path": base_path,
            "has_subdomain": True
        }

    # -------------------------------
    # Case 4: Simple domain (example.com)
    # -------------------------------
    if len(parts) == 2:
        return {
            "base_domain": host,
            "full_host": host,
            "base_path": base_path,
            "has_subdomain": False
        }

    # -------------------------------
    # Case 5: Single label (localhost, internal host)
    # -------------------------------
    return {
        "base_domain": host,
        "full_host": host,
        "base_path": base_path,
        "has_subdomain": False
    }

print(f"{parse_host("s3.192.168.1.10")}\n")
print(f"{parse_host("https://gc.s3.192.168.1.10/Bruh")}\n")
print(f"{parse_host("http://cdn.s3.storage.10.0.0.5")}\n")
print(f"{parse_host("s3.example.com")}\n")
print(f"{parse_host("http://bruh.ex.s3.gc.example.com/CVS")}\n")
print(f"{parse_host("example.com/test")}\n")
print(f"{parse_host("http://192.168.1.10")}\n")
print(f"{parse_host("http://.s.192.168.1.10")}\n")
