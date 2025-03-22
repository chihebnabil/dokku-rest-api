from flask import Flask, jsonify, request
import subprocess
import os
import json
import logging
import jwt
import datetime
import hashlib
import uuid
from functools import wraps

app = Flask(__name__)

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", str(uuid.uuid4()))
TOKEN_EXPIRATION = int(os.getenv("TOKEN_EXPIRATION", "3600"))  # 1 hour by default
ADMIN_USERNAME = os.getenv("DOKKU_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("DOKKU_ADMIN_PASSWORD", "pass")  # Default should be changed in production

# Hash the admin password if it's stored in plaintext
stored_password_hash = os.getenv("DOKKU_ADMIN_PASSWORD_HASH")
if not stored_password_hash:
    stored_password_hash = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()

# List of public paths that don't require authentication
PUBLIC_PATHS = ["/", "/health", "/docs", "/login"]

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if token is in headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split('Bearer ')[1]
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            # Decode the token
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data['username']
            
            # Check if token is expired (redundant as jwt.decode will do this, but keeping for clarity)
            if 'exp' in data and datetime.datetime.fromtimestamp(data['exp']) < datetime.datetime.utcnow():
                return jsonify({'error': 'Token has expired'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

@app.before_request
def check_auth():
    """Middleware to enforce authentication."""
    path = request.path.rstrip("/")
    
    # Allow public paths and static files without authentication
    if path in PUBLIC_PATHS or request.path.startswith("/static"):
        logger.debug(f"Skipping auth for public path: {request.path}")
        return
        
    # Skip auth check for OPTIONS requests (CORS preflight)
    if request.method == 'OPTIONS':
        return
        
    # For all other paths, require a valid token
    token = None
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization']
        if auth_header.startswith('Bearer '):
            token = auth_header.split('Bearer ')[1]
    
    if not token:
        logger.warning(f"No token provided for {request.path}")
        return jsonify({'error': 'Token is missing'}), 401
    
    try:
        # Decode the token
        jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        logger.warning(f"Expired token used for {request.path}")
        return jsonify({'error': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        logger.warning(f"Invalid token used for {request.path}")
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/')
def index():
    return jsonify({"message": "Welcome to the Dokku API!", "version": "2.0"})

@app.route('/login', methods=['POST'])
def login():
    """User login endpoint that generates a JWT token"""
    auth = request.get_json()
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
        
    username = auth.get('username')
    password = auth.get('password')
    
    # Check credentials
    if username != ADMIN_USERNAME:
        logger.warning(f"Login attempt with invalid username: {username}")
        return jsonify({'error': 'Invalid credentials'}), 401
        
    # Hash the provided password and compare with stored hash
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if password_hash != stored_password_hash:
        logger.warning(f"Login attempt with invalid password for user: {username}")
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Generate token
    expiration = datetime.datetime.utcnow() + datetime.timedelta(seconds=TOKEN_EXPIRATION)
    token_data = {
        'username': username,
        'exp': expiration
    }
    token = jwt.encode(token_data, SECRET_KEY, algorithm="HS256")
    
    logger.info(f"User {username} logged in successfully")
    return jsonify({
        'token': token,
        'expires_at': expiration.isoformat(),
        'token_type': 'Bearer'
    })

@app.route('/token/validate', methods=['GET'])
@token_required
def validate_token(current_user):
    """Endpoint to validate if a token is still valid"""
    return jsonify({
        'valid': True,
        'username': current_user
    })

@app.route('/token/refresh', methods=['POST'])
@token_required
def refresh_token(current_user):
    """Endpoint to refresh a valid token"""
    expiration = datetime.datetime.utcnow() + datetime.timedelta(seconds=TOKEN_EXPIRATION)
    token_data = {
        'username': current_user,
        'exp': expiration
    }
    token = jwt.encode(token_data, SECRET_KEY, algorithm="HS256")
    
    return jsonify({
        'token': token,
        'expires_at': expiration.isoformat(),
        'token_type': 'Bearer'
    })

# ===== APP MANAGEMENT =====

@app.route('/apps', methods=['GET'])
@token_required
def list_apps(current_user):
    """List all applications with their status"""
    try:
        # Get list of all apps
        apps_result = subprocess.run(
            ["dokku", "--quiet", "apps:list"],
            capture_output=True,
            text=True,
            check=True
        )
        app_names = [app for app in apps_result.stdout.strip().split('\n') if app]
        
        # Initialize result with app details
        apps_with_status = []
        
        # For each app, get its status information
        for app_name in app_names:
            app_info = {"name": app_name}
            
            try:
                # Get deployment status
                ps_result = subprocess.run(
                    ["dokku", "--quiet", "ps:report", app_name],
                    capture_output=True,
                    text=True
                )
                
                if ps_result.returncode == 0:
                    ps_output = ps_result.stdout.strip()
                    
                    # Extract status info
                    status = "unknown"
                    deploy_count = 0
                    running = False
                    
                    for line in ps_output.split('\n'):
                        if "Status" in line and ":" in line:
                            status_value = line.split(':', 1)[1].strip()
                            app_info["status"] = status_value
                            running = "running" in status_value.lower()
                        elif "Deployed" in line and ":" in line:
                            app_info["deployed"] = "true" in line.split(':', 1)[1].strip().lower()
                        elif "Restore" in line and ":" in line:
                            app_info["restore"] = "true" in line.split(':', 1)[1].strip().lower()
                    
                    app_info["running"] = running
                    
                    # Get URL if available
                    try:
                        url_result = subprocess.run(
                            ["dokku", "--quiet", "url", app_name],
                            capture_output=True,
                            text=True
                        )
                        if url_result.returncode == 0:
                            app_info["url"] = url_result.stdout.strip()
                    except:
                        pass
            except Exception as e:
                logger.warning(f"Error getting status for app {app_name}: {str(e)}")
                app_info["status_error"] = str(e)
            
            apps_with_status.append(app_info)
            
        return jsonify({"apps": apps_with_status})
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e)}), 500

@app.route('/apps', methods=['POST'])
@token_required
def create_app(current_user):
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
        logger.info(f"User {current_user} created app {app_name}")
        return jsonify({"message": f"Application {app_name} created successfully"}), 201
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

@app.route('/apps/<app_name>', methods=['GET'])
@token_required
def get_app(current_user, app_name):
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
@token_required
def delete_app(current_user, app_name):
    """Delete an application"""
    try:
        subprocess.run(
            ["dokku", "apps:destroy", app_name, "--force"],
            capture_output=True,
            text=True,
            check=True
        )
        logger.info(f"User {current_user} deleted app {app_name}")
        return jsonify({"message": f"Application {app_name} deleted successfully"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

@app.route('/apps/<app_name>/restart', methods=['POST'])
@token_required
def restart_app(current_user, app_name):
    """Restart an application"""
    try:
        subprocess.run(
            ["dokku", "ps:restart", app_name],
            capture_output=True,
            text=True,
            check=True
        )
        logger.info(f"User {current_user} restarted app {app_name}")
        return jsonify({"message": f"Application {app_name} restarted successfully"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

# ===== ENVIRONMENT VARIABLE MANAGEMENT =====

@app.route('/apps/<app_name>/env', methods=['GET'])
@token_required
def get_env_vars(current_user, app_name):
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
@token_required
def set_env_var(current_user, app_name):
    """Set environment variables for an application"""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No environment variables provided"}), 400
    
    try:
        # Create a temporary file with the environment variables
        temp_env_file = f"/tmp/dokku_temp_env_{uuid.uuid4()}.txt"
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
        
        logger.info(f"User {current_user} set environment variables for app {app_name}")
        return jsonify({"message": "Environment variables set successfully"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/apps/<app_name>/env/<env_name>', methods=['DELETE'])
@token_required
def unset_env_var(current_user, app_name, env_name):
    """Unset an environment variable for an application"""
    try:
        subprocess.run(
            ["dokku", "config:unset", app_name, env_name],
            capture_output=True,
            text=True,
            check=True
        )
        logger.info(f"User {current_user} unset environment variable {env_name} for app {app_name}")
        return jsonify({"message": f"Environment variable {env_name} unset successfully"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

# ===== DEPLOYMENT MANAGEMENT =====

@app.route('/apps/<app_name>/logs', methods=['GET'])
@token_required
def get_app_logs(current_user, app_name):
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
@token_required
def get_domains(current_user, app_name):
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
@token_required
def add_domain(current_user, app_name):
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
        logger.info(f"User {current_user} added domain {domain} to app {app_name}")
        return jsonify({"message": f"Domain {domain} added successfully"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

@app.route('/apps/<app_name>/domains/<domain>', methods=['DELETE'])
@token_required
def remove_domain(current_user, app_name, domain):
    """Remove a domain from an application"""
    try:
        subprocess.run(
            ["dokku", "domains:remove", app_name, domain],
            capture_output=True,
            text=True,
            check=True
        )
        logger.info(f"User {current_user} removed domain {domain} from app {app_name}")
        return jsonify({"message": f"Domain {domain} removed successfully"}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

# ===== PLUGIN MANAGEMENT =====

@app.route('/plugins', methods=['GET'])
@token_required
def list_plugins(current_user):
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
@token_required
def get_proxy_status(current_user, app_name):
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
@token_required
def update_proxy_status(current_user, app_name):
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
        
        logger.info(f"User {current_user} set proxy status to {enabled} for app {app_name}")    
        return jsonify({"message": message}), 200
    except subprocess.CalledProcessError as e:
        return jsonify({"error": str(e.stderr)}), 500

# ===== SYSTEM INFORMATION =====

@app.route('/system/version', methods=['GET'])
@token_required
def get_dokku_version(current_user):
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
@token_required
def get_system_report(current_user):
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

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({"status": "healthy"})

@app.route('/docs', methods=['GET'])
def api_docs():
    """API documentation"""
    # You can expand this with more detailed docs
    endpoints = [
        {"path": "/login", "method": "POST", "description": "Authenticate and get a token"},
        {"path": "/token/validate", "method": "GET", "description": "Validate a token"},
        {"path": "/token/refresh", "method": "POST", "description": "Refresh a valid token"},
        {"path": "/apps", "method": "GET", "description": "List all applications"},
        {"path": "/apps", "method": "POST", "description": "Create a new application"},
        # Add all other endpoints here
    ]
    
    return jsonify({
        "api_version": "2.0",
        "description": "Dokku API with JWT authentication",
        "endpoints": endpoints
    })

if __name__ == "__main__":
    # Check if required packages are installed
    try:
        import jwt
    except ImportError:
        print("PyJWT package is required. Install it with: pip install pyjwt")
        exit(1)
        
    # Generate a warning if using default credentials
    if ADMIN_USERNAME == "admin" and ADMIN_PASSWORD == "pass":
        logger.warning("Using default admin credentials. This is insecure!")
        logger.warning("Set DOKKU_ADMIN_USERNAME and DOKKU_ADMIN_PASSWORD environment variables")
    
    # Start the server
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("DEBUG", "False").lower() == "true"
    
    # In production, ensure debug mode is off
    if os.environ.get("ENVIRONMENT") == "production" and debug:
        logger.warning("Debug mode should not be enabled in production")
        debug = False
    
    logger.info(f"Starting Dokku API server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)
