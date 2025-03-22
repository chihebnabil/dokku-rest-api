# Dokku REST API

This plugin provides a REST API for managing your Dokku instance. Below are the steps to install, configure, and use the plugin.

## Installation

Install the Dokku REST API plugin:

```bash
dokku plugin:install https://github.com/chihebnabil/dokku-rest-api
```

You may need to install Flask and PyJWT:

```bash
sudo apt-get install -y python3-flask
pip install pyjwt
```

## Configuration

The API can be configured using the following environment variables:

- `JWT_SECRET_KEY` - Secret key for JWT token generation (default: auto-generated UUID).
- `TOKEN_EXPIRATION` - Token expiration time in seconds (default: 3600 seconds / 1 hour).
- `DOKKU_ADMIN_USERNAME` - Admin username for authentication (default: `admin`).
- `DOKKU_ADMIN_PASSWORD` - Admin password for authentication (default: `pass`). **Change this in production!**
- `DOKKU_ADMIN_PASSWORD_HASH` - SHA-256 hash of the admin password (optional, will be auto-generated if not provided).
- `PORT` - Port to listen on (default: 5000).
- `DEBUG` - Enable debug mode (default: False).

## Authentication

All endpoints except the following public paths require authentication using a JWT token:

- `/` - Welcome message.
- `/health` - Health check.
- `/docs` - API documentation.
- `/login` - Login endpoint to obtain a JWT token.

To authenticate, include the JWT token in the `Authorization` header:

```plaintext
Authorization: Bearer <your-jwt-token>
```

### Login Endpoint

To obtain a JWT token, send a POST request to `/login` with the admin credentials:

```bash
curl -X POST -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "your-password"}' \
     http://your-server:5000/login
```

#### Response:

```json
{
  "token": "<jwt-token>",
  "expires_at": "<expiration-time>",
  "token_type": "Bearer"
}
```

## Usage

Start the API server:

```bash
dokku api:start
```

Stop the API server:

```bash
dokku api:stop
```

## Endpoints

### Base Endpoints

| Method | Endpoint  | Description |
|--------|----------|-------------|
| GET    | `/`      | Welcome message, no authentication required |
| GET    | `/health`| Health check, no authentication required |
| GET    | `/docs`  | API documentation, no authentication required |

### Authentication Endpoints

| Method | Endpoint  | Description |
|--------|----------|-------------|
| POST   | `/login` | Authenticate and obtain a JWT token |
| GET    | `/token/validate` | Validate a JWT token (requires authentication) |
| POST   | `/token/refresh`  | Refresh a valid JWT token (requires authentication) |

### Application Management

| Method | Endpoint | Description |
|--------|---------|-------------|
| GET    | `/apps` | List all applications |
| POST   | `/apps` | Create a new application (Requires JSON body: `{"name": "app-name"}`) |
| GET    | `/apps/<app_name>` | Get application details including URL and status |
| DELETE | `/apps/<app_name>` | Delete an application |
| POST   | `/apps/<app_name>/restart` | Restart an application |

### Environment Variable Management

| Method | Endpoint | Description |
|--------|---------|-------------|
| GET    | `/apps/<app_name>/env` | Get all environment variables for an application |
| POST   | `/apps/<app_name>/env` | Set environment variables (Requires JSON body: `{"KEY1": "value1", "KEY2": "value2"}`) |
| DELETE | `/apps/<app_name>/env/<env_name>` | Unset a specific environment variable |

### Domain Management

| Method | Endpoint | Description |
|--------|---------|-------------|
| GET    | `/apps/<app_name>/domains` | Get domains for an application |
| POST   | `/apps/<app_name>/domains` | Add a domain (Requires JSON body: `{"domain": "example.com"}`) |
| DELETE | `/apps/<app_name>/domains/<domain>` | Remove a domain from an application |

### Proxy Management

| Method | Endpoint | Description |
|--------|---------|-------------|
| GET    | `/proxy/<app_name>` | Get proxy status and configuration for an application |
| PUT    | `/proxy/<app_name>` | Enable or disable proxy (Requires JSON body: `{"enabled": true}`) |

### Plugin Management

| Method | Endpoint | Description |
|--------|---------|-------------|
| GET    | `/plugins` | List all installed plugins |

### System Information

| Method | Endpoint | Description |
|--------|---------|-------------|
| GET    | `/system/version` | Get Dokku version |
| GET    | `/system/report` | Get system report including scheduler information |

## Examples

### List all applications

```bash
curl -H "Authorization: Bearer <your-jwt-token>" http://your-server:5000/apps
```

### Create a new application

```bash
curl -X POST -H "Authorization: Bearer <your-jwt-token>" -H "Content-Type: application/json" \
     -d '{"name":"my-new-app"}' \
     http://your-server:5000/apps
```

### Set environment variables

```bash
curl -X POST -H "Authorization: Bearer <your-jwt-token>" -H "Content-Type: application/json" \
     -d '{"DATABASE_URL":"postgres://user:pass@host:5432/db", "NODE_ENV":"production"}' \
     http://your-server:5000/apps/my-app/env
```

### Enable proxy for an application

```bash
curl -X PUT -H "Authorization: Bearer <your-jwt-token>" -H "Content-Type: application/json" \
     -d '{"enabled":true}' \
     http://your-server:5000/proxy/my-app
```

## Response Format

All endpoints return JSON responses. Success responses typically include a message or requested data. Error responses include an error message and appropriate HTTP status code.

### Success Response Example

```json
{
  "apps": ["app1", "app2", "app3"]
}
```

### Error Response Example

```json
{
  "error": "Application not found"
}
```

