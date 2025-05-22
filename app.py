import argparse
import sys
import os
import json
from ipaddress import ip_address, AddressValueError

try:
    from OTXv2 import OTXv2
    from OTXv2 import IndicatorTypes
except ImportError:
    print("[!] Error: OTXv2 package not found. Please install it with: pip install OTXv2", file=sys.stderr)
    sys.exit(1)

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

def validate_ip_address(ip_str):
    """Validate if the provided string is a valid IP address."""
    try:
        ip_obj = ip_address(ip_str)
        return ip_obj
    except (AddressValueError, ValueError):
        return None

def format_otx_response(data, ip_str):
    """Format the OTX response data for readable output."""
    print(f"\n=== AlienVault OTX Threat Intelligence Report for {ip_str} ===\n")
    
    if not data:
        print("[*] No threat intelligence data found for this IP address.")
        return
    
    # General information
    if 'general' in data:
        general = data['general']
        print("[*] GENERAL INFORMATION:")
        print(f"    IP Address: {general.get('indicator', 'N/A')}")
        print(f"    Type: {general.get('type', 'N/A')}")
        print(f"    Country: {general.get('country_name', 'N/A')} ({general.get('country_code', 'N/A')})")
        print(f"    City: {general.get('city', 'N/A')}")
        print(f"    ASN: {general.get('asn', 'N/A')}")
        print(f"    Latitude: {general.get('latitude', 'N/A')}")
        print(f"    Longitude: {general.get('longitude', 'N/A')}")
        print(f"    Accuracy Radius: {general.get('accuracy_radius', 'N/A')}")
        print(f"    Pulse Info Count: {general.get('pulse_info', {}).get('count', 0)}")
        print()
    
    # Reputation data
    if 'reputation' in data:
        reputation = data['reputation']
        if reputation.get('threat_score', 0) > 0:
            print("[!] REPUTATION ALERTS:")
            print(f"    Threat Score: {reputation.get('threat_score', 0)}")
            print(f"    First Seen: {reputation.get('first_seen', 'N/A')}")
            print(f"    Last Seen: {reputation.get('last_seen', 'N/A')}")
            print(f"    Counts: {reputation.get('counts', {})}")
            print()
    
    # Geo data
    if 'geo' in data:
        geo = data['geo']
        print("[*] GEOGRAPHIC INFORMATION:")
        print(f"    Country: {geo.get('country_name', 'N/A')} ({geo.get('country_code', 'N/A')})")
        print(f"    Region: {geo.get('region', 'N/A')}")
        print(f"    City: {geo.get('city', 'N/A')}")
        print(f"    Postal Code: {geo.get('postal_code', 'N/A')}")
        print(f"    Coordinates: {geo.get('latitude', 'N/A')}, {geo.get('longitude', 'N/A')}")
        print(f"    ASN: {geo.get('asn', 'N/A')}")
        print()
    
    # Malware data
    if 'malware' in data and data['malware'].get('data'):
        print("[!] MALWARE ASSOCIATIONS:")
        # Collect and count malware names
        malware_counts = {}
        for malware in data['malware']['data']:
            name = malware.get('detections', {}).get('name', 'Unknown')
            malware_counts[name] = malware_counts.get(name, 0) + 1
        
        # Display unique malware names with counts
        for name, count in sorted(malware_counts.items()):
            if count > 1:
                print(f"    - {name} (x{count})")
            else:
                print(f"    - {name}")
        print()
    
    # Pulse data
    if 'general' in data and data['general'].get('pulse_info', {}).get('pulses'):
        pulses = data['general']['pulse_info']['pulses'][:3]  # Show first 3 pulses
        if pulses:
            print("[!] RELATED THREAT PULSES:")
            for pulse in pulses:
                print(f"    Pulse: {pulse.get('name', 'N/A')}")
                print(f"    Created: {pulse.get('created', 'N/A')}")
                print(f"    Tags: {', '.join(pulse.get('tags', []))}")
                print(f"    TLP: {pulse.get('TLP', 'N/A')}")
                print(f"    Author: {pulse.get('author_name', 'N/A')}")
                print()

def main():
    parser = argparse.ArgumentParser(description="Lookup IP Address threat intelligence using AlienVault OTX API.")
    parser.add_argument('ip_address', help='IP Address to Get Threat Intelligence For')
    parser.add_argument('--api-key', help='OTX API Key (or set OTX_API_KEY environment variable)')
    parser.add_argument('--raw', action='store_true', help='Output raw JSON response')
    args = parser.parse_args()

    ip_str = args.ip_address

    # Validate IP address format
    ip_obj = validate_ip_address(ip_str)
    if ip_obj is None:
        print(f"[!] Error: '{ip_str}' is not a valid IPv4 or IPv6 address.", file=sys.stderr)
        return 1

    # Get API key from argument or environment variable
    api_key = args.api_key or os.getenv('OTX_API_KEY')
    if not api_key:
        print("[!] Error: OTX API Key required. Set OTX_API_KEY environment variable or use --api-key argument.", file=sys.stderr)
        print("[*] You can get an API key by registering at https://otx.alienvault.com", file=sys.stderr)
        return 1

    # Determine indicator type
    if ip_obj.version == 4:
        indicator_type = IndicatorTypes.IPv4
    else:
        indicator_type = IndicatorTypes.IPv6

    print(f"[*] Querying AlienVault OTX for IP: {ip_str}")
    print(f"[*] IP Version: IPv{ip_obj.version}")

    try:
        # Initialize OTX client
        otx = OTXv2(api_key)
        
        # Get detailed information about the IP
        print("[*] Fetching threat intelligence data...")
        response = otx.get_indicator_details_full(indicator_type, ip_str)
        
        if args.raw:
            # Output raw JSON
            print(json.dumps(response, indent=2, default=str))
        else:
            # Format and display the response
            format_otx_response(response, ip_str)
        
        return 0

    except Exception as e:
        print(f"[!] Error querying OTX API: {e}", file=sys.stderr)
        return 1

### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ### --- ###

if __name__ == "__main__":
    sys.exit(main())