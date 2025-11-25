from flask import Flask, request, render_template, redirect, url_for, jsonify, session
from functions import *
import neo4j
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
from functools import wraps
from datetime import datetime


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET") or "dev-secret-please-change"
# app.logger.setLevel(logging.DEBUG)
# app.logger.propagate = True

# handler = logging.StreamHandler()
# handler.setLevel(logging.DEBUG)
# app.logger.addHandler(handler)

app.logger.debug("Flask logger initialized")

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard', methods=['GET'])
def dashboard():
    # require login
    if not session.get("user"):
        return redirect(url_for("login"))
    return render_template('dashboard.html')


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "authentication required"}), 401
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = session.get("user")
        if not user:
            return jsonify({"error": "authentication required"}), 401
        # load users
        users = load_users()
        u = users.get(user)
        if not u or u.get("role") != "admin":
            return jsonify({"error": "admin required"}), 403
        return f(*args, **kwargs)
    return decorated


USERS_FILE = os.path.join(os.path.dirname(__file__), "users.json")
TASKS_FILE = os.path.join(os.path.dirname(__file__), "tasks.json")

def load_users():
    # Load users, return dict. If file missing or corrupt, raise to caller to decide.
    with open(USERS_FILE, "r") as fh:
        return json.load(fh)

def save_users(users):
    tmp = USERS_FILE + ".tmp"
    try:
        with open(tmp, "w") as fh:
            json.dump(users, fh, indent=2)
        try:
            os.replace(tmp, USERS_FILE)
        except FileNotFoundError:
            # tmp disappeared for some reason; fall back to direct write
            with open(USERS_FILE, "w") as fh:
                json.dump(users, fh, indent=2)
    except Exception:
        app.logger.exception("Failed to write users file atomically; falling back to direct write")
        with open(USERS_FILE, "w") as fh:
            json.dump(users, fh, indent=2)

def load_tasks():
    # Load tasks, return dict. If file missing or corrupt, return empty dict.
    if not os.path.exists(TASKS_FILE):
        return {}
    try:
        with open(TASKS_FILE, "r") as fh:
            return json.load(fh)
    except Exception:
        app.logger.exception("Failed to read tasks file, returning empty tasks")
        return {}

def save_tasks(tasks):
    tmp = TASKS_FILE + ".tmp"
    try:
        with open(tmp, "w") as fh:
            json.dump(tasks, fh, indent=2)
        try:
            os.replace(tmp, TASKS_FILE)
        except FileNotFoundError:
            # tmp not found, fallback to direct write
            with open(TASKS_FILE, "w") as fh:
                json.dump(tasks, fh, indent=2)
    except Exception:
        app.logger.exception("Failed to write tasks file atomically; falling back to direct write")
        with open(TASKS_FILE, "w") as fh:
            json.dump(tasks, fh, indent=2)


def ensure_initial_state():
    """Ensure user and task files exist and are in a clean state on startup.

    Behavior:
      - If `users.json` is missing or malformed, create it with a generated admin password.
      - If `users.json` exists but has no 'admin' user, add an admin with generated password.
      - Always clear `tasks.json` to an empty object to avoid leftover test data on deploy.
    """
    created_admin = False
    admin_password = None

    # Ensure users file exists and contains an admin
    try:
        if not os.path.exists(USERS_FILE):
            # create admin
            users = {"admin": {"password": generate_password_hash("admin"), "role": "admin"}}
            save_users(users)
            created_admin = True
        else:
            try:
                users = load_users()
            except Exception:
                users = {}
            if not isinstance(users, dict):
                users = {}
            if "admin" not in users:
                users["admin"] = {"password": generate_password_hash("admin"), "role": "admin"}
                save_users(users)
                created_admin = True
    except Exception as e:
        app.logger.exception("Error ensuring users file: %s", e)

    # Clear tasks.json to avoid leftover test data
    try:
        save_tasks({})
    except Exception as e:
        app.logger.exception("Error clearing tasks file: %s", e)

    if created_admin:
        # Log the generated admin password so operator can copy it on first deploy
        app.logger.info("Created 'admin' user with generated password: %s", admin_password)
    else:
        app.logger.info("Users file OK; ensured tasks.json cleared on startup.")


# Run initial state enforcement on import/startup
ensure_initial_state()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    username = request.form.get('username')
    password = request.form.get('password')
    if not username or not password:
        return render_template('login.html', error='Missing username or password')
    users = load_users()
    u = users.get(username)
    if not u or not check_password_hash(u['password'], password):
        return render_template('login.html', error='Invalid credentials')
    session['user'] = username
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload():
    try:
        if not session.get("user"):
            return {"error": "authentication required"}, 401
        files = request.files.getlist("file")  # multiple files input
        if not files:
            return {"error": "No files uploaded"}, 400
        
        url = request.form.get("url")
        if not url:
            return {"error": "Missing url"}, 400


        file_contents = []
        for f in files:
            text = f.read().decode("utf-8")
            file_contents.append(text)

        parsed = gobuster2json(file_contents, url)

        # Insert all parsed data into Neo4j (use execute_write for neo4j v5+)
        with driver.session() as neo_session:
            for entry in parsed["domains"]:
                neo_session.execute_write(insert_json, entry)
            for entry in parsed["base_domains"]:
                neo_session.execute_write(insert_json, entry)

        return {"status": "ok", "parsed": parsed}
    except Exception as e:
        return {"error": str(e)}


@app.route('/api/graph', methods=['POST'])
def api_graph():

    payload = request.get_json(silent=True) or {}
    cypher = payload.get("query")
    params = payload.get("params", {})

    if not cypher:
        return jsonify({"error": "Missing Cypher query"}), 400

    if not session.get("user"):
        return jsonify({"error": "authentication required"}), 401

    nodes = {}
    edges = []

    with driver.session() as neo_session:
        result = neo_session.run(cypher, params)

        for rec in result:

            # Add all nodes in this row
            for key, value in rec.items():
                # Handle single Node
                if isinstance(value, neo4j.graph.Node):
                    add_node(nodes, value)

                # Handle single Relationship
                elif isinstance(value, neo4j.graph.Relationship):
                    rel = value
                    start = rel.start_node
                    end = rel.end_node

                    add_node(nodes, start)
                    add_node(nodes, end)

                    edges.append({
                        "from": start.element_id,
                        "to": end.element_id,
                        "label": rel.type,
                        "properties": dict(rel)
                    })

                # Handle Paths (variable-length relationships)
                elif isinstance(value, neo4j.graph.Path):
                    for n in value.nodes:
                        add_node(nodes, n)
                    for r in value.relationships:
                        edges.append({
                            "from": r.start_node.element_id,
                            "to": r.end_node.element_id,
                            "label": r.type,
                            "properties": dict(r)
                        })

                # Handle lists/collections returned (e.g., r* returns a list of relationships)
                elif isinstance(value, (list, tuple)):
                    for item in value:
                        if isinstance(item, neo4j.graph.Node):
                            add_node(nodes, item)
                        elif isinstance(item, neo4j.graph.Relationship):
                            add_node(nodes, item.start_node)
                            add_node(nodes, item.end_node)
                            edges.append({
                                "from": item.start_node.element_id,
                                "to": item.end_node.element_id,
                                "label": item.type,
                                "properties": dict(item)
                            })
                        elif isinstance(item, neo4j.graph.Path):
                            for n in item.nodes:
                                add_node(nodes, n)
                            for r in item.relationships:
                                edges.append({
                                    "from": r.start_node.element_id,
                                    "to": r.end_node.element_id,
                                    "label": r.type,
                                    "properties": dict(r)
                                })
                        else:
                            # ignore primitives inside lists
                            pass

                else:
                    # ignore primitives
                    pass

    return jsonify({
        "nodes": list(nodes.values()),
        "edges": edges
    })


@app.route('/manage-operators', methods=['GET', 'POST'])
@admin_required
def manage_operators():
    # Return a simple page where admin can create/delete/change password
    if request.method == 'GET':
        users = load_users()
        return render_template('manage_operators.html', users=users)
    data = request.form
    action = data.get('action')
    users = load_users()
    if action == 'create':
        uname = data.get('username')
        pwd = data.get('password')
        role = data.get('role') or 'operator'
        if not uname or not pwd:
            return jsonify({"error": "missing fields"}), 400
        users[uname] = {"password": generate_password_hash(pwd), "role": role}
        save_users(users)
        return redirect(url_for('manage_operators'))
    elif action == 'delete':
        uname = data.get('username')
        if uname in users:
            users.pop(uname)
            save_users(users)
        return redirect(url_for('manage_operators'))
    elif action == 'passwd':
        uname = data.get('username')
        pwd = data.get('password')
        if uname in users and pwd:
            users[uname]['password'] = generate_password_hash(pwd)
            save_users(users)
        return redirect(url_for('manage_operators'))
    return jsonify({"error": "unknown action"}), 400


@app.route('/api/users', methods=['GET'])
@login_required
def api_users():
    """Return list of users for building the Tasks UI.

    - If the requester is an admin, return all users (so admin can view all operator lists).
    - Otherwise, return only non-admin operator usernames.
    """
    users = load_users()
    current = session.get('user')
    current_info = users.get(current, {}) if current else {}
    if current_info.get('role') == 'admin':
        operators = list(users.keys())
    else:
        operators = [u for u, info in users.items() if info.get('role') != 'admin']
    return jsonify({"operators": operators})


@app.route('/api/mark-checked', methods=['POST'])
@login_required
def api_mark_checked():
    payload = request.get_json(silent=True) or {}
    node_id = payload.get('node_id')
    checked = payload.get('checked', True)
    user = session.get('user')
    if not node_id:
        return jsonify({"error": "node_id required"}), 400
    tasks = load_tasks()
    entry = tasks.get(node_id, {"checked_by": {}, "notes": ""})
    if checked:
        entry['checked_by'][user] = datetime.utcnow().isoformat()
    else:
        entry['checked_by'].pop(user, None)
    tasks[node_id] = entry
    save_tasks(tasks)
    return jsonify({"ok": True, "entry": entry})


@app.route('/api/node-tasks/<node_id>', methods=['GET'])
@login_required
def api_node_tasks(node_id):
    tasks = load_tasks()
    return jsonify(tasks.get(node_id, {"checked_by": {}, "notes": ""}))


@app.route('/api/node-notes', methods=['POST'])
@login_required
def api_node_notes():
    payload = request.get_json(silent=True) or {}
    node_id = payload.get('node_id')
    notes = payload.get('notes', '')
    if not node_id:
        return jsonify({"error": "node_id required"}), 400
    tasks = load_tasks()
    entry = tasks.get(node_id, {"checked_by": {}, "notes": ""})
    entry['notes'] = notes
    tasks[node_id] = entry
    save_tasks(tasks)
    return jsonify({"ok": True})


@app.route('/api/export', methods=['GET'])
@login_required
def api_export():
    # Export nodes and relationships as JSON
    nodes_out = []
    rels_out = []
    with driver.session() as s:
        res = s.run("MATCH (n) OPTIONAL MATCH (n)-[r]->(m) RETURN n, r, m LIMIT 10000")
        for rec in res:
            n = rec['n']
            nodes_out.append({'id': n.element_id, 'labels': list(n.labels), 'props': dict(n)})
            r = rec.get('r')
            m = rec.get('m')
            if r and m:
                rels_out.append({'id': r.id, 'type': r.type, 'start': r.start_node.element_id, 'end': r.end_node.element_id, 'props': dict(r)})
    return jsonify({'nodes': nodes_out, 'relationships': rels_out})



# @app.route("/api/delete-node", methods=["POST"])
# def delete_node():
#     payload = request.get_json(silent=True) or {}
#     node_id = payload.get("nodeId")
#     mode = payload.get("mode")

#     if mode == "cascade":
#         cypher = """
#         MATCH (n) WHERE elementId(n) = $nodeId WITH n MATCH (n)-[*0..]->(child) DETACH DELETE child
#         """
#     elif mode == "children":
#         cypher = """
#         MATCH (n) WHERE elementId(n) = $nodeId WITH n MATCH (n)-[*1..]->(child) DETACH DELETE child
#         """
#     elif mode == "node":
#         cypher = """
#         MATCH (n) WHERE elementId(n) = $nodeId DETACH DELETE n
#         """
#     elif mode == "edge": # Delete all child edges only
#         cypher = """
#         MATCH (n) WHERE elementId(n) = $nodeId WITH n MATCH (n)-[r]->(child) DELETE r
#         """
#     else:
#         return "ERROR: Invalid Mode"

#     with driver.session() as session:
#         session.run(cypher, {"nodeId": node_id})

#     return "Ok"



# @app.route("/api/delete-edges", methods=["POST"])
# def delete_edges():
#     payload = request.get_json(silent=True) or {}
#     rel_id = payload.get("relationship_id")

#     if not rel_id:
#         return jsonify({"error": "No relationship IDs provided"}), 400

#     cypher = """
#         MATCH (n)-[r]->(m) WHERE elementId(r) = $id DETACH DELETE r
#     """

#     with driver.session() as session:
#         session.run(cypher, {"id": rel_id})

#     return "Ok"

@app.route("/api/execute-cypher", methods=["POST"])
def execute_cypher():
    payload = request.get_json(silent=True) or {}
    cypher = payload.get("query")
    params = payload.get("params", {})

    if not cypher:
        return jsonify({"error": "Cypher query missing"}), 400

    with driver.session() as neo_session:
        try:
            result = neo_session.run(cypher, params)

            processed = []
            try:
                for r in result:
                    row = {}
                    for k,v in r.items():
                        # convert neo4j types to JSON-friendly
                        if isinstance(v, neo4j.graph.Node):
                            row[k] = {"_type":"node", "element_id": v.element_id, "labels": list(v.labels), "props": dict(v)}
                        elif isinstance(v, neo4j.graph.Relationship):
                            row[k] = {"_type":"rel", "id": v.id, "type": v.type, "start": v.start_node.element_id, "end": v.end_node.element_id, "props": dict(v)}
                        elif isinstance(v, neo4j.graph.Path):
                            row[k] = {"_type":"path", "nodes": [{"element_id": n.element_id, "labels": list(n.labels), "props": dict(n)} for n in v.nodes], "rels": [{"type": rr.type, "start": rr.start_node.element_id, "end": rr.end_node.element_id, "props": dict(rr)} for rr in v.relationships]}
                        else:
                            # primitive value
                            row[k] = v
                    processed.append(row)
            except Exception as fetch_err:
                # Error during result fetching
                raise Exception(f"Error fetching results: {str(fetch_err)}")

            # Try to consume summary safely
            summary = {}
            try:
                summary = result.consume().counters._dict
            except:
                # If consume fails, just return empty summary
                summary = {}
            
            return jsonify({"records": processed, "summary": summary})

        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({"error": str(e)}), 500


@app.route("/api/unchecked-endpoints", methods=["GET"])
@login_required
def get_unchecked_endpoints():
    """
    Get unchecked endpoints for a specific operator or globally.
    Query params:
      - operator: operator name (or 'all' for globally unchecked)
    """
    operator = request.args.get("operator")
    if not operator:
        return jsonify({"error": "operator parameter required"}), 400

    tasks = load_tasks()
    
    # Fetch all Path and Subdomain nodes from Neo4j
    with driver.session() as neo_session:
        try:
            # Get all Path nodes
            result = neo_session.run("""
                MATCH (p:Path)
                RETURN elementId(p) AS id, p.path AS path, p.domain AS domain, p.code AS code
            """)
            endpoints = []
            for record in result:
                node_id = record["id"]
                endpoints.append({
                    "id": node_id,
                    "label": f"{record['domain']}{record['path']}",
                    "type": "path",
                    "path": record["path"],
                    "domain": record["domain"],
                    "code": record["code"]
                })
            
            # Also get Subdomains
            result = neo_session.run("""
                MATCH (s:Subdomain)
                RETURN elementId(s) AS id, s.host AS host
            """)
            for record in result:
                node_id = record["id"]
                endpoints.append({
                    "id": node_id,
                    "label": record["host"],
                    "type": "subdomain",
                    "host": record["host"]
                })
            
            # Filter by checked status
            filtered = []
            if operator == "all":
                # Show endpoints that NOBODY has checked
                for ep in endpoints:
                    node_id = ep["id"]
                    task_info = tasks.get(node_id, {})
                    checked_by = task_info.get("checked_by", {})
                    if not checked_by:  # Empty dict means nobody checked it
                        filtered.append(ep)
            else:
                # Show endpoints this operator has NOT checked
                for ep in endpoints:
                    node_id = ep["id"]
                    task_info = tasks.get(node_id, {})
                    checked_by = task_info.get("checked_by", {})
                    if operator not in checked_by:  # Operator not in the list
                        filtered.append(ep)
            
            return jsonify({"endpoints": filtered})
        except Exception as e:
            return jsonify({"error": str(e)}), 500


@app.route("/api/all-endpoints", methods=["GET"])
@login_required
def get_all_endpoints():
    """Get all endpoints (Path and Subdomain nodes)"""
    with driver.session() as neo_session:
        try:
            endpoints = []
            
            # Get all Path nodes
            result = neo_session.run("""
                MATCH (p:Path)
                RETURN elementId(p) AS id, p.path AS path, p.domain AS domain, p.code AS code
            """)
            for record in result:
                node_id = record["id"]
                endpoints.append({
                    "id": node_id,
                    "label": f"{record['domain']}{record['path']}",
                    "type": "path",
                    "path": record["path"],
                    "domain": record["domain"],
                    "code": record["code"]
                })
            
            # Get all Subdomains
            result = neo_session.run("""
                MATCH (s:Subdomain)
                RETURN elementId(s) AS id, s.host AS host
            """)
            for record in result:
                node_id = record["id"]
                endpoints.append({
                    "id": node_id,
                    "label": record["host"],
                    "type": "subdomain",
                    "host": record["host"]
                })
            
            return jsonify({"endpoints": endpoints})
        except Exception as e:
            return jsonify({"error": str(e)}), 500


@app.route("/api/delete-edge", methods=["POST"])
@login_required
def delete_edge():
    """Delete a relationship from the graph"""
    payload = request.get_json(silent=True) or {}
    start_id = payload.get("start_id")
    end_id = payload.get("end_id")
    rel_type = payload.get("rel_type")
    
    if not start_id or not end_id:
        return jsonify({"error": "start_id and end_id required"}), 400
    
    try:
        with driver.session() as neo_session:
            if rel_type:
                # Delete specific relationship type
                cypher = f"""
                    MATCH (a) WHERE elementId(a) = $start_id
                    MATCH (b) WHERE elementId(b) = $end_id
                    MATCH (a)-[r:{rel_type}]->(b)
                    DELETE r
                """
            else:
                # Delete any relationship between nodes
                cypher = """
                    MATCH (a) WHERE elementId(a) = $start_id
                    MATCH (b) WHERE elementId(b) = $end_id
                    MATCH (a)-[r]->(b)
                    DELETE r
                """
            neo_session.run(cypher, start_id=start_id, end_id=end_id)
        return jsonify({"ok": True})
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# This allows you to run the app directly with `python app.py`
if __name__ == '__main__':
    app.run(debug=True)