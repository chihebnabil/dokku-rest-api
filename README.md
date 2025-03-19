# Dokku REST Api

This plugin provides a REST API for managing your Dokku instance. Below are the steps to install, configure, and use the plugin.

## Installation

Install the Dokku REST API plugin:

```bash
dokku plugin:install https://github.com/chihebnabil/dokku-rest-api
```

## Configuration

Set an environment variable for the API key.
Replace `your-secret-key-123` with a secure key of your choice:

```bash
export DOKKU_API_KEY=your-secret-key-123
```

Test the API by sending a request to the Dokku server. Replace YOUR_DOKKU_IP_ADD with your Dokku server's IP address:

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
