#!/usr/bin/env bash
set -eo pipefail
[[ $DOKKU_TRACE ]] && set -x

# Parse arguments
HOST="$1"
PORT="$2"

# Default values if not provided
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8080}"

# Function to handle requests and return JSON response
handle_request() {
  local request="$1"
  local method=$(echo "$request" | head -n 1 | cut -d' ' -f1)
  local path=$(echo "$request" | head -n 1 | cut -d' ' -f2)
  
  # Set content type to JSON
  echo "HTTP/1.1 200 OK"
  echo "Content-Type: application/json"
  echo "Access-Control-Allow-Origin: *"
  echo ""
  
  case "$path" in
    "/apps")
      if [ "$method" = "GET" ]; then
        # Get list of all apps
        apps=$(dokku apps:list | tail -n +2 | tr -d ' ')
        echo "{\"apps\": [" > /tmp/response.json
        
        # Build JSON array of apps
        first=true
        for app in $apps; do
          if [ "$first" = true ]; then
            first=false
          else
            echo "," >> /tmp/response.json
          fi
          echo "  {\"name\": \"$app\"}" >> /tmp/response.json
        done
        
        echo "]}" >> /tmp/response.json
        cat /tmp/response.json
        rm /tmp/response.json
      else
        echo "{\"error\": \"Method not allowed\", \"allowed\": [\"GET\"]}"
      fi
      ;;
      
    "/apps/"*)
      app_name=$(echo "$path" | cut -d'/' -f3)
      if [ -z "$app_name" ]; then
        echo "{\"error\": \"App name required\"}"
        return
      fi
      
      # Check if app exists
      if ! dokku apps:exists "$app_name" &>/dev/null; then
        echo "{\"error\": \"App not found\", \"app\": \"$app_name\"}"
        return
      fi
      
      case "$method" in
        "GET")
          # Get app details
          domains=$(dokku domains:report "$app_name" --domains)
          urls=$(dokku urls "$app_name" 2>/dev/null || echo "")
          config=$(dokku config:export "$app_name" 2>/dev/null | sed 's/export //g' | sed 's/"//g' || echo "")
          
          echo "{" > /tmp/response.json
          echo "  \"name\": \"$app_name\"," >> /tmp/response.json
          
          # Domains
          echo "  \"domains\": [" >> /tmp/response.json
          first=true
          for domain in $domains; do
            if [ "$first" = true ]; then
              first=false
            else
              echo "," >> /tmp/response.json
            fi
            echo "    \"$domain\"" >> /tmp/response.json
          done
          echo "  ]," >> /tmp/response.json
          
          # URLs
          echo "  \"urls\": [" >> /tmp/response.json
          first=true
          for url in $urls; do
            if [ "$first" = true ]; then
              first=false
            else
              echo "," >> /tmp/response.json
            fi
            echo "    \"$url\"" >> /tmp/response.json
          done
          echo "  ]," >> /tmp/response.json
          
          # Config (simplified)
          echo "  \"config\": {" >> /tmp/response.json
          first=true
          while IFS='=' read -r key value; do
            if [ -n "$key" ]; then
              if [ "$first" = true ]; then
                first=false
              else
                echo "," >> /tmp/response.json
              fi
              echo "    \"$key\": \"$value\"" >> /tmp/response.json
            fi
          done <<< "$config"
          echo "  }" >> /tmp/response.json
          
          echo "}" >> /tmp/response.json
          cat /tmp/response.json
          rm /tmp/response.json
          ;;
        *)
          echo "{\"error\": \"Method not allowed\", \"allowed\": [\"GET\"]}"
          ;;
      esac
      ;;
      
    "/health")
      echo "{\"status\": \"ok\", \"version\": \"1.0.0\"}"
      ;;
      
    *)
      echo "{\"error\": \"Not found\", \"endpoints\": [\"/apps\", \"/apps/{app_name}\", \"/health\"]}"
      ;;
  esac
}

# Start a simple HTTP server using netcat
echo "Starting REST API server on $HOST:$PORT"

# Check if we have nc or ncat
if command -v nc &> /dev/null; then
  NC_CMD="nc"
elif command -v ncat &> /dev/null; then
  NC_CMD="ncat"
else
  echo "Error: Neither nc nor ncat is installed. Please install one of them."
  exit 1
fi

# Function to handle a single connection
handle_connection() {
  local request=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    request="$request$line\n"
    if [[ -z "$line" ]]; then
      break
    fi
  done
  
  echo -e "$request" | handle_request "$request"
}

# Main server loop
while true; do
  if [[ "$NC_CMD" == "nc" ]]; then
    # Use nc (BSD style)
    echo -e "$(nc -l "$HOST" "$PORT")" | handle_connection
  else
    # Use ncat (Nmap style)
    ncat -l "$HOST" "$PORT" --keep-open --sh-exec "handle_connection"
  fi
done