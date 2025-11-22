import re
from urllib.parse import urlparse
from neo4j import GraphDatabase
from pathlib import Path



with open('../neo4j_auth.txt', 'r') as file:
    tmp = file.read()
    creds = tmp.rstrip().split('/')
driver = GraphDatabase.driver("bolt://127.0.0.1:7687", auth=("neo4j", creds[1]))



# Patterns
dir_pattern = re.compile(
    r"^(?P<path>/\S*)\s+"                       # /admin
    r"\(Status:\s*(?P<code>\d+)\)\s+"           # (Status: 200)
    r"\[Size:\s*(?P<size>\d+)\]",               # [Size: 123]
    re.IGNORECASE
)

vhost_pattern = re.compile(
    r"^(?P<host>[A-Za-z0-9._-]+)\s+Status:\s*(?P<code>\d+)\s*\[Size:\s*(?P<size>\d+)\]",
    re.IGNORECASE
)


# Parse the url to find the scan endpoints
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

def gobuster2json(upload, url):
    parsed_host = parse_host(url)
    base_domain = parsed_host["base_domain"]
    full_host = parsed_host["full_host"]
    base_path = parsed_host["base_path"]
    has_subdomain = parsed_host["has_subdomain"]
    output = {"domains": [], "base_domains": []}

    for data in upload:
        dir_results = []
        vhost_results = []
        seen_paths = set()

        for line in data.splitlines():
            if match := dir_pattern.search(line):
                raw_path = match.group("path").rstrip("/") or "/"
                if not raw_path.startswith("/"):
                    raw_path = "/" + raw_path

                # full_path under the scanned host's root (so base_path + raw_path)
                if base_path:
                    full_path = (base_path.rstrip("/") + raw_path)
                else:
                    full_path = raw_path
                # normalize
                full_path = "/" + "/".join([p for p in full_path.split("/") if p])

                if full_path in seen_paths:
                    continue
                seen_paths.add(full_path)

                # decide parent_type:
                # if scanned_host is a subdomain (3+ parts) we treat top-level parent as the subdomain;
                # otherwise, parent is a path under base_domain
               
                if has_subdomain:
                    parent_type = "subdomain"   # paths attach to the scanned host
                    parent = full_host            # store scanned host as parent
                else:
                    # find parent path relative to root
                    parent_path, _, _ = full_path.rpartition("/")
                    if parent_path == "" or parent_path == "/":
                        parent_type = "domain"
                        parent = None
                    else:
                        parent_type = "path"
                        parent = "/" + parent_path.strip("/")

                dir_results.append({
                    "path": full_path,
                    "parent": parent,
                    "parent_type": parent_type,
                    "code": int(match.group("code")) if match.group("code") else None,
                    "size": int(match.group("size")) if match.group("size") else None,
                    "scanned_host": full_host,
                    "base_domain": base_domain
                })

            elif match := vhost_pattern.search(line):
                vhost_results.append({
                    "host": match.group("host"),
                    "code": int(match.group("code")) if match.group("code") else None,
                    "size": int(match.group("size")) if match.group("size") else None
                })

        if dir_results:
            output["domains"].append({
                "scanned_host": full_host,
                "base_domain": base_domain,
                "base_path": base_path,
                "results": dir_results
            })
        if vhost_results:
            output["base_domains"].append({
                "base_domain": base_domain,
                "subdomains": vhost_results
            })

    return output


# Insert the data into the neo4j database
def insert_json(tx, data):
    # data contains scanned_host, base_domain, results
    scanned_host = data.get("scanned_host")
    base_domain = data.get("base_domain")
    if not base_domain:
        return

    # ensure base Domain node exists
    tx.run("MERGE (d:Domain {name: $base_domain})", base_domain=base_domain)

    if "results" in data:
        for r in data.get("results", []):
            path = r["path"]
            parent = r.get("parent")
            parent_type = r.get("parent_type")
            code = r.get("code")
            size = r.get("size")
            # Merge Path keyed by base_domain + path. Also store scanned_host for future repairs.
            tx.run("""
                MERGE (p:Path {domain: $base_domain, path: $path})
                SET p.code = $code, p.size = $size, p.scanned_host = coalesce(p.scanned_host, $scanned_host)
            """, base_domain=base_domain, path=path, code=code, size=size, scanned_host=scanned_host)

            if parent_type == "subdomain":
                # attach path under the Subdomain node with host = scanned_host
                tx.run("""
                    MERGE (s:Subdomain {host: $host})
                    SET s.domain = coalesce(s.domain, $base_domain)
                    MERGE (d:Domain {name: $base_domain})
                    MERGE (d)-[:Subdomain]->(s)
                    MERGE (p:Path {domain: $base_domain, path: $path})
                    MERGE (s)-[:Subdirectory]->(p)
                """, host=scanned_host, base_domain=base_domain, path=path)
            elif parent_type == "path":
                tx.run("""
                    MERGE (pp:Path {domain: $base_domain, path: $parent})
                    MERGE (p:Path {domain: $base_domain, path: $path})
                    SET p.code = $code, p.size = $size
                    MERGE (pp)-[:Subdirectory]->(p)
                """, base_domain=base_domain, parent=parent, path=path, code=code, size=size)
            else:
                # domain_root -> attach to Domain
                tx.run("""
                    MATCH (d:Domain {name: $base_domain})
                    MERGE (p:Path {domain: $base_domain, path: $path})
                    MERGE (d)-[:Subdirectory]->(p)
                """, base_domain=base_domain, path=path)
    elif "subdomains" in data:
        base_domain_name = data["base_domain"] 
        # tx.run("MERGE (b:Domain {name: $domain})", domain=base_domain_name) 
        for sub in data["subdomains"]: 
            tx.run("""
                MERGE (s:Subdomain {domain: $domain, host: $host}) 
                SET s.code = $code, s.size = $size 
                WITH s 
                MATCH (b:Domain {name: $domain}) 
                MERGE (b)-[:Subdomain]->(s)
                """, domain=base_domain_name, host=sub["host"], code=sub["code"], size=sub["size"])



def add_node(nodes, neo_node):
    node_id = neo_node.element_id

    # Try common label fields
    label = (
        neo_node.get("path") or
        neo_node.get("host") or
        neo_node.get("name") or
        neo_node.get("domain") or
        neo_node.get("ip") or
        "Node"
    )

    nodes[node_id] = {
        "group": list(neo_node.labels)[0] if neo_node.labels else "Unknown",
        "id": node_id,
        "label": label,
        "domain": neo_node.get("domain") or neo_node.get("name")
    }