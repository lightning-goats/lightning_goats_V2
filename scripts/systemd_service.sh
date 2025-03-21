#!/bin/bash

# Define color codes for terminal output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the absolute path to the app directory
APP_DIR=$(dirname $(dirname $(realpath $0)))
echo -e "${BLUE}Application directory:${NC} $APP_DIR"

# Create systemd service file
SERVICE_FILE="lightning_goats.service"

cat << EOF > $SERVICE_FILE
[Unit]
Description=Lightning Goats FastAPI Application
After=network.target

[Service]
User=$(whoami)
Group=$(id -gn)
WorkingDirectory=$APP_DIR
ExecStart=/usr/local/bin/gunicorn fastapi_ap:app --workers 1 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8090
Environment="PATH=$PATH"
Restart=on-failure
RestartSec=5s
# Graceful stop settings
TimeoutStopSec=30s
KillSignal=SIGTERM
KillMode=mixed

# Security settings
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

echo -e "${GREEN}Created service file:${NC} $SERVICE_FILE"
echo

# Display instructions
echo -e "${BLUE}Installation instructions:${NC}"
echo "1. Copy the service file to systemd directory:"
echo "   sudo cp $SERVICE_FILE /etc/systemd/system/"
echo
echo "2. Reload systemd to recognize the new service:"
echo "   sudo systemctl daemon-reload"
echo
echo "3. Enable the service to start on boot:"
echo "   sudo systemctl enable lightning_goats.service"
echo
echo "4. Start the service:"
echo "   sudo systemctl start lightning_goats.service"
echo
echo "5. Check the service status:"
echo "   sudo systemctl status lightning_goats.service"
echo
echo -e "${GREEN}Additional commands:${NC}"
echo "- To stop the service:   sudo systemctl stop lightning_goats.service"
echo "- To restart:            sudo systemctl restart lightning_goats.service"
echo "- To view logs:          sudo journalctl -u lightning_goats.service -f"
