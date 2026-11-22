"""Flask application for the CyberShield AI URL indicator demo."""

from flask import Flask, jsonify, render_template, request

from url_checks import analyze_url
from message_checks import analyze_message

app = Flask(__name__)


@app.get("/")
def home():
    """Show the scanner page."""
    return render_template("index.html")


@app.post("/api/scan")
def scan_url():
    """Analyze URL text and return explainable indicators as JSON."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a JSON object with a 'url' field."}), 400

    submitted_url = data.get("url")
    if not isinstance(submitted_url, str) or not submitted_url.strip():
        return jsonify({"error": "Enter a URL to scan."}), 400

    result, error = analyze_url(submitted_url.strip())
    if error:
        return jsonify({"error": error}), 400
    return jsonify(result)


@app.post("/api/scan-message")
def scan_message():
    """Analyze message text and return explainable indicators as JSON."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a JSON object with a 'message' field."}), 400

    message = data.get("message")
    if not isinstance(message, str) or not message.strip():
        return jsonify({"error": "Enter a message to scan."}), 400

    result, error = analyze_message(message.strip())
    if error:
        return jsonify({"error": error}), 400
    return jsonify(result)


@app.post("/api/scan-combined")
def scan_combined():
    """Scan message wording and an optional URL independently."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Send a JSON object with 'message' and optional 'url' fields."}), 400

    message = data.get("message")
    url = data.get("url", "")
    if not isinstance(message, str) or not message.strip():
        return jsonify({"error": "Enter a message to scan."}), 400
    if not isinstance(url, str):
        return jsonify({"error": "The URL field must be text."}), 400

    message_result, error = analyze_message(message.strip())
    if error:
        return jsonify({"error": error}), 400

    url_result = None
    if url.strip():
        url_result, error = analyze_url(url.strip())
        if error:
            return jsonify({"error": f"URL: {error}"}), 400

    return jsonify({"message_result": message_result, "url_result": url_result})


if __name__ == "__main__":
    # Debug mode is convenient for local practice. Do not expose this server publicly.
    app.run(debug=True)
