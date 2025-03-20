from flask import Flask, jsonify, request
import subprocess
import os
import json

app = Flask(__name__)
API_KEY = os.getenv("DOKKU_API_KEY")  # Add security via API key

# List of public paths
PUBLIC_PATHS = ["/", "/health", "/docs"]

@app.before_request
def check_auth():
    # Skip authentication for explicitly public paths
    if request.path in PUBLIC_PATHS or request.path.startswith("/static"):
        return  
    
    # Ensure API key is provided and correct
    if request.headers.get("X-API-Key") != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

@app.route('/')
def index():
    return jsonify({"message": "Welcome to the Dokku API!"})

# ===== APP MANAGEMENT =====

@app.route('/apps', methods=['GET'])
def list_apps():
    """List all applications"""
    try:
        result = subprocess.run(
            ["dokku", "--quiet", "apps:list"],
            capture_output=True,
            text=True,
            check=True
        )
        apps = [app for app in result.stdout.strip().split('\n') if app]
        return jsonify({"apps": apps})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e)}), 500

@app.route('/apps', methods=['POST'])
def create_app():
    """Create a new application"""
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({"error": "Application name is required"}), 400
    
    app_name = data['name']
    try:
        subprocess.run(
            ["dokku", "apps:create", app_name],
            capture_output=True,
            text=True,
            check=True
        )
        return jsonify({"message": f"Application {app_name} created successfully"}), 201
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

@app.route('/apps/<app_name>', methods=['GET'])
def get_app(app_name):
    """Get application details"""
    try:
        # Check if app exists
        apps_result = subprocess.run(
            ["dokku", "--quiet", "apps:list"],
            capture_output=True,
            text=True,
            check=True
        )
        apps = [app for app in apps_result.stdout.strip().split('\n') if app]
        if app_name not in apps:
            return jsonify({"error": "Application not found"}), 404
        
        # Get app info
        info = {}
        
        # Get URL
        try:
            url_result = subprocess.run(
                ["dokku", "--quiet", "url", app_name],
                capture_output=True,
                text=True
            )
            if url_result.returncode == 0:
                info["url"] = url_result.stdout.strip()
        except:
            pass
        
        # Get status
        try:
            status_result = subprocess.run(
                ["dokku", "--quiet", "ps:report", app_name],
                capture_output=True,
                text=True
            )
            if status_result.returncode == 0:
                status_lines = status_result.stdout.strip().split('\n')
                for line in status_lines:
                    if ":" in line:
                        key, value = line.split(':', 1)
                        info[key.strip()] = value.strip()
        except:
            pass
            
        return jsonify({"app": app_name, "info": info})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

@app.route('/apps/<app_name>', methods=['DELETE'])
def delete_app(app_name):
    """Delete an application"""
    try:
        subprocess.run(
            ["dokku", "apps:destroy", app_name, "--force"],
            capture_output=True,
            text=True,
            check=True
        )
        return jsonify({"message": f"Application {app_name} deleted successfully"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

@app.route('/apps/<app_name>/restart', methods=['POST'])
def restart_app(app_name):
    """Restart an application"""
    try:
        subprocess.run(
            ["dokku", "ps:restart", app_name],
            capture_output=True,
            text=True,
            check=True
        )
        return jsonify({"message": f"Application {app_name} restarted successfully"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

# ===== ENVIRONMENT VARIABLE MANAGEMENT =====

@app.route('/apps/<app_name>/env', methods=['GET'])
def get_env_vars(app_name):
    """Get all environment variables for an application"""
    try:
        result = subprocess.run(
            ["dokku", "config:export", "--format", "json", app_name],
            capture_output=True,
            text=True,
            check=True
        )
        try:
            env_vars = json.loads(result.stdout.strip())
        except json.JSONDecodeError:
            # Handle case where output isn't proper JSON
            env_vars_str = result.stdout.strip()
            if env_vars_str.startswith('{') and env_vars_str.endswith('}'):
                # Try to parse manually if it looks like JSON
                env_vars = {}
                for line in env_vars_str.strip('{}').split(','):
                    if ':' in line:
                        key, value = line.split(':', 1)
                        env_vars[key.strip(' "')] = value.strip(' "')
            else:
                # Otherwise, return the raw output
                return jsonify({"env": result.stdout.strip()}), 200
                
        return jsonify({"env": env_vars})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

@app.route('/apps/<app_name>/env', methods=['POST'])
def set_env_var(app_name):
    """Set environment variables for an application"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No environment variables provided"}), 400
    
    try:
        # Create a temporary file with the environment variables
        temp_env_file = "/tmp/dokku_temp_env.txt"
        with open(temp_env_file, 'w') as f:
            for key, value in data.items():
                f.write(f"{key}={value}\n")
        
        # Set the environment variables
        subprocess.run(
            ["dokku", "config:set", "--no-restart", app_name, f"@{temp_env_file}"],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Clean up
        os.remove(temp_env_file)
        
        return jsonify({"message": "Environment variables set successfully"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/apps/<app_name>/env/<env_name>', methods=['DELETE'])
def unset_env_var(app_name, env_name):
    """Unset an environment variable for an application"""
    try:
        subprocess.run(
            ["dokku", "config:unset", app_name, env_name],
            capture_output=True,
            text=True,
            check=True
        )
        return jsonify({"message": f"Environment variable {env_name} unset successfully"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

# ===== DEPLOYMENT MANAGEMENT =====

@app.route('/apps/<app_name>/logs', methods=['GET'])
def get_app_logs(app_name):
    """Get logs for an application"""
    try:
        lines = request.args.get('lines', '100')
        result = subprocess.run(
            ["dokku", "logs", app_name, "--num", lines],
            capture_output=True,
            text=True,
            check=True
        )
        logs = result.stdout.strip()
        return jsonify({"logs": logs})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

@app.route('/apps/<app_name>/domains', methods=['GET'])
def get_domains(app_name):
    """Get domains for an application"""
    try:
        result = subprocess.run(
            ["dokku", "domains:report", app_name],
            capture_output=True,
            text=True,
            check=True
        )
        domains_report = result.stdout.strip()
        
        # Extract domains from the report
        domains = []
        for line in domains_report.split('\n'):
            if 'Domains app vhosts' in line:
                domains_str = line.split('Domains app vhosts:')[1].strip()
                domains = [d.strip() for d in domains_str.split(',') if d.strip()]
                break
        
        return jsonify({"domains": domains})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

@app.route('/apps/<app_name>/domains', methods=['POST'])
def add_domain(app_name):
    """Add a domain to an application"""
    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({"error": "Domain is required"}), 400
    
    domain = data['domain']
    try:
        subprocess.run(
            ["dokku", "domains:add", app_name, domain],
            capture_output=True,
            text=True,
            check=True
        )
        return jsonify({"message": f"Domain {domain} added successfully"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

@app.route('/apps/<app_name>/domains/<domain>', methods=['DELETE'])
def remove_domain(app_name, domain):
    """Remove a domain from an application"""
    try:
        subprocess.run(
            ["dokku", "domains:remove", app_name, domain],
            capture_output=True,
            text=True,
            check=True
        )
        return jsonify({"message": f"Domain {domain} removed successfully"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

# ===== PLUGIN MANAGEMENT =====

@app.route('/plugins', methods=['GET'])
def list_plugins():
    """List all installed plugins"""
    try:
        result = subprocess.run(
            ["dokku", "plugin:list"],
            capture_output=True,
            text=True,
            check=True
        )
        plugins = [plugin for plugin in result.stdout.strip().split('\n') if plugin]
        return jsonify({"plugins": plugins})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

@app.route('/proxy/<app_name>', methods=['GET'])
def get_proxy_status(app_name):
    """Get proxy status for an application"""
    try:
        result = subprocess.run(
            ["dokku", "proxy:report", app_name],
            capture_output=True,
            text=True,
            check=True
        )
        proxy_report = result.stdout.strip()
        
        # Parse the proxy report
        proxy_info = {}
        for line in proxy_report.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                proxy_info[key.strip()] = value.strip()
                
        return jsonify({"proxy": proxy_info})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

@app.route('/proxy/<app_name>', methods=['PUT'])
def update_proxy_status(app_name):
    """Enable or disable proxy for an application"""
    data = request.get_json()
    if not data or 'enabled' not in data:
        return jsonify({"error": "Enabled status is required"}), 400
    
    enabled = data['enabled']
    try:
        if enabled:
            subprocess.run(
                ["dokku", "proxy:enable", app_name],
                capture_output=True,
                text=True,
                check=True
            )
            message = f"Proxy enabled for {app_name}"
        else:
            subprocess.run(
                ["dokku", "proxy:disable", app_name],
                capture_output=True,
                text=True,
                check=True
            )
            message = f"Proxy disabled for {app_name}"
            
        return jsonify({"message": message}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

# ===== SERVER INFORMATION =====

@app.route('/system/version', methods=['GET'])
def get_dokku_version():
    """Get Dokku version"""
    try:
        result = subprocess.run(
            ["dokku", "version"],
            capture_output=True,
            text=True,
            check=True
        )
        version = result.stdout.strip()
        return jsonify({"version": version})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

@app.route('/system/report', methods=['GET'])
def get_system_report():
    """Get system report"""
    try:
        result = subprocess.run(
            ["dokku", "scheduler:report"],
            capture_output=True,
            text=True,
            check=True
        )
        report = result.stdout.strip()
        
        # Parse the report
        system_info = {}
        for line in report.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                system_info[key.strip()] = value.strip()
                
        return jsonify({"system": system_info})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "False").lower() == "true"
    app.run(host='0.0.0.0', port=port, debug=debug)
