from flask import Flask, jsonify
import subprocess
import os

app = Flask(__name__)
API_KEY = os.getenv("DOKKU_API_KEY")  # Add security via API key

# Basic authentication middleware
@app.before_request
def check_auth():
    if request.headers.get("X-API-Key") != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

@app.route('/apps', methods=['GET'])
def list_apps():
    try:
        result = subprocess.run(
            ["dokku", "apps:list"],
            capture_output=True,
            text=True,
            check=True
        )
        apps = result.stdout.strip().split('\n')
        return jsonify({"apps": apps})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e)}), 500

@app.route('/app/<app_name>', methods=['GET'])
def app_details(app_name):
    try:
        result = subprocess.run(
            ["dokku", "config:show", app_name],
            capture_output=True,
            text=True,
            check=True
        )
        return jsonify({"config": result.stdout})
    except subprocess.CalledProcessError:
        return jsonify({"error": "App not found"}), 404

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)