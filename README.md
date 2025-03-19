# Dokku REST Api

This plugin provides a REST API for managing your Dokku instance. Below are the steps to install, configure, and use the plugin.

## Installation

Install the Dokku REST API plugin:

```bash
dokku plugin:install https://github.com/chihebnabil/dokku-rest-api
```

then set the `DOKKU_API_KEY` in your environment

```bash
export DOKKU_API_KEY="your-super-secure-not-public-key"
```

## Authentication

All endpoints except the root endpoint (`/`) require authentication using an API key.

```
Header: X-API-Key: your-api-key
```

## Configuration

The API can be configured using the following environment variables:

- `DOKKU_API_KEY` - API authentication key (required)
- `PORT` - Port to listen on (default: 5000)
- `DEBUG` - Enable debug mode (default: False)


Test the API by sending a request to the Dokku server. 
Replace YOUR_DOKKU_IP_ADD with your Dokku server's IP address:

```bash
curl -H "X-API-Key: $DOKKU_API_KEY" http://YOUR_DOKKU_IP_ADD:5000/
```

## Usage

```bash
dokku api:start
```

```bash
dokku api:stop
```

## Endpoints

### Base

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Welcome message, no authentication required |

### Application Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/apps` | List all applications |
| POST | `/apps` | Create a new application (Requires JSON body: `{"name": "app-name"}`) |
| GET | `/apps/<app_name>` | Get application details including URL and status |
| DELETE | `/apps/<app_name>` | Delete an application |
| POST | `/apps/<app_name>/restart` | Restart an application |
| GET | `/apps/<app_name>/logs` | Get application logs (Optional query param: `lines=100`) |

### Environment Variable Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/apps/<app_name>/env` | Get all environment variables for an application |
| POST | `/apps/<app_name>/env` | Set environment variables (Requires JSON body: `{"KEY1": "value1", "KEY2": "value2"}`) |
| DELETE | `/apps/<app_name>/env/<env_name>` | Unset a specific environment variable |

### Domain Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/apps/<app_name>/domains` | Get domains for an application |
| POST | `/apps/<app_name>/domains` | Add a domain (Requires JSON body: `{"domain": "example.com"}`) |
| DELETE | `/apps/<app_name>/domains/<domain>` | Remove a domain from an application |

### Proxy Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/proxy/<app_name>` | Get proxy status and configuration for an application |
| PUT | `/proxy/<app_name>` | Enable or disable proxy (Requires JSON body: `{"enabled": true}`) |

### Plugin Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/plugins` | List all installed plugins |

### System Information

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/system/version` | Get Dokku version |
| GET | `/system/report` | Get system report including scheduler information |

## Examples

### List all applications

```bash
curl -H "X-API-Key: your-api-key" http://your-server:5000/apps
```

### Create a new application

```bash
curl -X POST -H "X-API-Key: your-api-key" -H "Content-Type: application/json" \
     -d '{"name":"my-new-app"}' \
     http://your-server:5000/apps
```

### Set environment variables

```bash
curl -X POST -H "X-API-Key: your-api-key" -H "Content-Type: application/json" \
     -d '{"DATABASE_URL":"postgres://user:pass@host:5432/db", "NODE_ENV":"production"}' \
     http://your-server:5000/apps/my-app/env
```

### Enable proxy for an application

```bash
curl -X PUT -H "X-API-Key: your-api-key" -H "Content-Type: application/json" \
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

