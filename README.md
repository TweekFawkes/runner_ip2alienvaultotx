# runner_ip2alienvaultotx

This runner takes an IP address as input and uses the AlienVault OTX (Open Threat Exchange) Python SDK to gather threat intelligence information about that IP address.

## Features

- **Threat Intelligence Lookup**: Queries AlienVault OTX for comprehensive threat intelligence data
- **IP Validation**: Validates IPv4 and IPv6 addresses using Python's `ipaddress` module
- **Formatted Output**: Displays threat intelligence in a human-readable format
- **Raw JSON Output**: Option to output raw JSON response for further processing
- **Geographic Information**: Shows country, city, ASN, and coordinates
- **Reputation Scoring**: Displays threat scores and reputation data
- **Malware Associations**: Lists associated malware if any
- **Related Threat Pulses**: Shows related threat intelligence pulses

## Requirements

- Python 3.6+
- AlienVault OTX API Key (free registration at [https://otx.alienvault.com](https://otx.alienvault.com))

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
# Set your API key as an environment variable
export OTX_API_KEY="your_api_key_here"

# Query an IP address
python app.py 8.8.8.8
```

### Alternative Usage with API Key Argument

```bash
python app.py 8.8.8.8 --api-key your_api_key_here
```

### Raw JSON Output

```bash
python app.py 8.8.8.8 --raw
```

## Getting an API Key

1. Visit [https://otx.alienvault.com](https://otx.alienvault.com)
2. Create a free account
3. Go to your profile settings
4. Copy your API key

## Output Format

The script provides:
- **General Information**: IP details, country, city, ASN
- **Geographic Information**: Detailed location data
- **Reputation Alerts**: Threat scores and reputation data (if any)
- **Malware Associations**: Related malware samples (if any)
- **Related Threat Pulses**: Recent threat intelligence pulses mentioning this IP

## Example Runner Configuration (`runner.yaml`)

- **Name:** IP to AlienVault OTX Threat Intelligence
- **Description:** Uses AlienVault OTX Python SDK to gather threat intelligence for the provided IP address
- **Build:** Installs `python3` and required Python packages via `requirements.txt`
- **Input:** Requires an `ip_address` and `OTX_API_KEY` environment variable
- **Launch:** Executes `python app.py ${ip_address}`

