from flask import Flask, jsonify , request
import subprocess
import os

app = Flask(__name__)
API_KEY = os.getenv("DOKKU_API_KEY")  # Add security via API key

# Basic authentication middleware
@app.before_request
def check_auth():
    if request.headers.get("X-API-Key") != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

@app.route('/')
def index():
    return jsonify({"message": "Welcome to the Dokku API!"})

@app.route('/apps', methods=['GET'])
def list_apps():
    try:
        result = subprocess.run(
            ["dokku", "--quiet","apps:list"],
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
            ["dokku", "config:export", "--format", "json", app_name],  # Fixed argument splitting
            capture_output=True,
            text=True,
            check=True
        )
        app_info = result.stdout.strip()
        return jsonify({"app": app_info})
    except subprocess.CalledProcessError:
        return jsonify({"error": "App not found"}), 404


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)