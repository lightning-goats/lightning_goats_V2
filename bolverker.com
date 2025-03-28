##
# Redirect all HTTP traffic to HTTPS
##
server {
    listen 80;
    listen [::]:80;
    server_name bolverker.com www.bolverker.com lightning-goats.com www.lightning-goats.com;
    return 301 https://$host$request_uri;
}

##
# SSL Configuration, Reverse Proxy & HLS Streaming Support
##
server {
    listen [::]:443 ssl ipv6only=on; # Managed by Certbot
    listen 443 ssl;                  # Managed by Certbot
    server_name bolverker.com www.bolverker.com lightning-goats.com www.lightning-goats.com;
    root /var/www/html;
    index index.html;

    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/bolverker.com-0002/fullchain.pem; # Managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/bolverker.com-0002/privkey.pem; # Managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf;                          # Managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;                            # Managed by Certbot

    ##
    # Main location block for static files
    ##
    location / {
        try_files $uri $uri/ =404;
    }

    ##
    # HLS Streaming Support (served over HTTPS)
    ##
    location /hls {
        types {
            application/vnd.apple.mpegurl m3u8;
            video/mp2t ts;
        }
        root /var/www/html;
        add_header Cache-Control no-cache;
    }

    ##
    # Well-Known Directory for nostr.json and lnurlp
    ##
    location /.well-known/nostr.json {
        proxy_pass https://lnb.bolverker.com/nostrnip5/api/v1/domain/eGrBG7HWLJTiYyhxgEpMwz/nostr.json;
        proxy_set_header Host lnb.bolverker.com;
        proxy_ssl_server_name on;
        expires 5m;
        add_header Cache-Control "public, no-transform";
        proxy_cache nip5_cache;
        proxy_cache_lock on;
        proxy_cache_valid 200 300s;
        proxy_cache_use_stale error timeout invalid_header updating http_500 http_502 http_503 http_504;
    }

    location ~ ^/\.well-known/lnurlp/(.*) {
        proxy_pass https://lnb.bolverker.com/lnurlp/api/v1/well-known/$1;
    }

    ##
    # API Routes - Updated with new paths
    ##
    
    # Payment routes
    location /payments/balance {
        proxy_pass http://127.0.0.1:8090/payments/balance;
        add_header Accept "application/json";
        add_header 'Access-Control-Allow-Origin' "$http_origin" always;
        add_header 'Access-Control-Allow-Credentials' "true" always;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /payments/trigger_amount {
        proxy_pass http://127.0.0.1:8090/payments/trigger_amount;
        add_header Accept "application/json";
        add_header 'Access-Control-Allow-Origin' "$http_origin" always;
        add_header 'Access-Control-Allow-Credentials' "true" always;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /payments/convert/ {
        proxy_pass http://127.0.0.1:8090/payments/convert/;
        add_header Accept "application/json";
        add_header 'Access-Control-Allow-Origin' "$http_origin" always;
        add_header 'Access-Control-Allow-Credentials' "true" always;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Goat routes
    location /goats/feeder/status {
        proxy_pass http://127.0.0.1:8090/goats/feeder/status;
        add_header Accept "application/json";
        add_header 'Access-Control-Allow-Origin' "$http_origin" always;
        add_header 'Access-Control-Allow-Credentials' "true" always;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /goats/sats {
        proxy_pass http://127.0.0.1:8090/goats/sats;
        add_header Accept "application/json";
        add_header 'Access-Control-Allow-Origin' "$http_origin" always;
        add_header 'Access-Control-Allow-Credentials' "true" always;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /goats/feedings {
        proxy_pass http://127.0.0.1:8090/goats/feedings;
        add_header Accept "application/json";
        add_header 'Access-Control-Allow-Origin' "$http_origin" always;
        add_header 'Access-Control-Allow-Credentials' "true" always;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /goats/feeder/trigger {
        proxy_pass http://127.0.0.1:8090/goats/feeder/trigger;
        add_header Accept "application/json";
        add_header 'Access-Control-Allow-Origin' "$http_origin" always;
        add_header 'Access-Control-Allow-Credentials' "true" always;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # CyberHerd routes
    location /cyberherd/spots_remaining {
        proxy_pass http://127.0.0.1:8090/cyberherd/spots_remaining;
        add_header Accept "application/json";
        add_header 'Access-Control-Allow-Origin' "$http_origin" always;
        add_header 'Access-Control-Allow-Credentials' "true" always;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /cyberherd/members {
        proxy_pass http://127.0.0.1:8090/cyberherd/members;
        add_header Accept "application/json";
        add_header 'Access-Control-Allow-Origin' "$http_origin" always;
        add_header 'Access-Control-Allow-Credentials' "true" always;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Messages routes
    location /messages/ {
        proxy_pass http://127.0.0.1:8090/messages/;
        add_header Accept "application/json";
        add_header 'Access-Control-Allow-Origin' "$http_origin" always;
        add_header 'Access-Control-Allow-Credentials' "true" always;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Health check endpoint
    location /health {
        proxy_pass http://127.0.0.1:8090/health;
        add_header Accept "application/json";
        add_header 'Access-Control-Allow-Origin' "$http_origin" always;
        add_header 'Access-Control-Allow-Credentials' "true" always;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    ##
    # WebSocket Endpoints - Enhanced configuration
    ##
    location /ws {
        proxy_pass http://127.0.0.1:8090;  # Remove the /ws path to avoid double path
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Add these settings for more reliable WebSocket connections
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
        proxy_send_timeout 300s;
        
        # Add CORS headers to support WebSocket connections from other origins
        add_header 'Access-Control-Allow-Origin' "$http_origin" always;
        add_header 'Access-Control-Allow-Credentials' 'true' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'DNT,X-CustomHeader,Keep-Alive,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Content-Range,Range,Authorization' always;
    }

    location /api/v1/ws/ {
        proxy_pass http://127.0.0.1:3002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        
        # Add additional timeout settings
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
        proxy_send_timeout 300s;
    }

    ##
    # Additional Endpoint: /get_received_data
    ##
    location /get_received_data {
        proxy_pass http://10.8.0.6:5000/get_received_data;
        # Hide the upstream Access-Control-Allow-Origin header
        proxy_hide_header Access-Control-Allow-Origin;
        # Add your own Access-Control-Allow-Origin header
        add_header 'Access-Control-Allow-Origin' "$http_origin" always;
        add_header 'Access-Control-Allow-Credentials' "true" always;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    ##
    # L402 Authentication API Routes
    ##
    location /l402/ {
        proxy_pass http://127.0.0.1:8090/l402/;
        add_header Accept "application/json";
        add_header 'Access-Control-Allow-Origin' "$http_origin" always;
        add_header 'Access-Control-Allow-Credentials' "true" always;
        add_header 'Access-Control-Allow-Methods' "GET, POST, OPTIONS" always;
        add_header 'Access-Control-Allow-Headers' "DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization" always;
        
        # Handle OPTIONS method for CORS preflight requests
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Max-Age' 1728000;
            add_header 'Content-Type' 'text/plain; charset=utf-8';
            add_header 'Content-Length' 0;
            return 204;
        }
        
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
