# ⚡ Lightning Goats V2 ⚡

A Bitcoin Lightning Network powered application that allows the internet to collectively feed goats through cryptocurrency micropayments.

## Overview

Lightning Goats V2 is a full-stack application that connects the Bitcoin Lightning Network to real-world actions. Users can send Bitcoin Lightning payments to trigger a physical goat feeder using Openhab and ip power switches, watch live video feeds of the goats being fed, and join the "CyberHerd" community.

![Lightning Goats](https://lightning-goats.com/images/lightninggoatslogo1.png)

## Features

- **Lightning Network Integration**: Accept and process Bitcoin Lightning payments
- **Real-time Interface**: WebSocket-powered live updates for payments and feeding events
- **CyberHerd Community**: Social features using Nostr protocol integration
- **Automatic Feeding**: Trigger physical goat feeder when payment thresholds are reached
- **IoT Integration**: Connect with OpenHAB for home automation and sensor data
- **Payment Processing**: Handle Lightning payments with robust retry mechanisms
- **Responsive Web Interface**: Watch the goats and monitor feeding progress
- **Message Templates**: Customizable messages for various events

## Tech Stack

- **Backend**: FastAPI (Python)
- **Database**: SQLite with SQLAlchemy and async support
- **Real-time**: WebSockets for live updates
- **Payments**: LNBits integration
- **Social**: Nostr protocol for decentralized messaging
- **IoT**: OpenHAB integration for physical control
- **Frontend**: HTML/CSS/JavaScript with GSAP animations

## Installation

### Prerequisites

- Python 3.9+
- LNBits instance
- OpenHAB setup (optional for IoT features)
- Nostr key (for social features)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/lightning_goatsV2.git
   cd lightning_goatsV2
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. Initialize the database:
   ```bash
   python -m scripts.initialize_db
   ```

## Configuration

Configure your application by editing the `.env` file:

```
# Authentication and API Keys
OH_AUTH_1=your_openhab_auth_key
HERD_WALLET=your_lnbits_wallet_id
HERD_KEY=your_lnbits_api_key
CYBERHERD_KEY=your_cyberherd_key
NOS_SEC=your_nostr_private_key
HEX_KEY=your_hex_key

# Service URLs
LNBITS_URL=http://your_lnbits_server:port
OPENHAB_URL=http://your_openhab_server:port
HERD_WEBSOCKET=ws://your_lnbits_server:port/api/v1/ws/your_wallet_id

# CyberHerd Configuration
PREDEFINED_WALLET_ADDRESS=your_lightning_address
PREDEFINED_WALLET_ALIAS=Your_Name
MAX_HERD_SIZE=10
TRIGGER_AMOUNT_SATS=1250
```

## Usage

Start the FastAPI server:

```bash
/usr/bin/gunicorn -w 1 -k uvicorn.workers.UvicornWorker main:app --bind 0.0.0.0:8090
```

The application will be available at http://localhost:8000

## API Endpoints

- `/payments/` - Payment-related endpoints
- `/goats/` - Goat-related endpoints
- `/cyberherd/` - CyberHerd community endpoints
- `/ws/` - WebSocket endpoint for real-time updates

## CyberHerd Feature

The CyberHerd is a community feature that allows Lightning Network users to:

1. Join a collective of micropayment participants
2. Receive shares of payments proportional to their contribution
3. Participate in community activities through Nostr integration
4. Have their profiles displayed in the web interface

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The Bitcoin and Lightning Network communities
- All the members of the CyberHerd
- The real goats who make this project actually meaningful

## Contact

For questions or support, reach out on Nostr or open an issue on GitHub.