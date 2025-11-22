from flask import Flask, request, render_template, redirect, url_for, jsonify
from functions import *
import neo4j
# import logging


app = Flask(__name__)
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
    return render_template('dashboard.html')

@app.route('/upload', methods=['POST'])
def upload():
    try:
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

        # Insert all parsed data into Neo4j
        with driver.session() as session:
            for entry in parsed["domains"]:
                session.write_transaction(insert_json, entry)
            for entry in parsed["base_domains"]:
                session.write_transaction(insert_json, entry)

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

    nodes = {}
    edges = []

    with driver.session() as session:
        result = session.run(cypher, params)

        for rec in result:

            # Add all nodes in this row
            for key, value in rec.items():

                # Case 1 — Node
                if isinstance(value, neo4j.graph.Node):
                    add_node(nodes, value)

                # Case 2 — Relationship
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

                # Case 3 — Paths
                elif isinstance(value, neo4j.graph.Path):
                    # Add path nodes
                    for n in value.nodes:
                        add_node(nodes, n)
                    # Add path relationships
                    for r in value.relationships:
                        edges.append({
                            "from": r.start_node.element_id,
                            "to": r.end_node.element_id,
                            "label": r.type,
                            "properties": dict(r)
                        })

    return jsonify({
        "nodes": list(nodes.values()),
        "edges": edges
    })



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

    with driver.session() as session:
        try:
            result = session.run(cypher, params)

            data = {
                "records": [r.data() for r in result],
                "summary": result.consume().counters._dict
            }

            return jsonify(data)

        except Exception as e:
            return jsonify({"error": str(e)}), 500



# This allows you to run the app directly with `python app.py`
if __name__ == '__main__':
    app.run(debug=True)