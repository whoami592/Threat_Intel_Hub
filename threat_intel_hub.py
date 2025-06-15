import requests
import json
from pyfiglet import Figlet
from datetime import datetime
import sys

# Stylish Banner
def display_banner():
    f = Figlet(font='slant')
    print(f.renderText('ThreatIntelHub'))
    print("=" * 70)
    print("        Coded by: Pakistani Ethical Hacker Mr Sabaz Ali Khan")
    print("        Nationality: Pakistani | Role: AMI Group Admin")
    print("        Version: 1.0 | Date: June 15, 2025")
    print("=" * 70)
    print("\nWelcome to ThreatIntelHub - Your Open-Source Threat Intelligence Tool\n")

# Function to fetch threat intelligence from AlienVault OTX
def fetch_threat_data(api_key, indicator_type, indicator):
    base_url = "https://otx.alienvault.com/api/v1/indicators"
    headers = {"X-OTX-API-KEY": api_key}
    
    try:
        url = f"{base_url}/{indicator_type}/{indicator}/general"
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching data: {e}")
        return None

# Function to display threat intelligence data
def display_threat_data(data):
    if not data:
        print("[-] No data to display.")
        return
    
    print("\n[+] Threat Intelligence Data:")
    print("-" * 50)
    print(f"Indicator: {data.get('indicator', 'N/A')}")
    print(f"Type: {data.get('type', 'N/A')}")
    print(f"Pulse Count: {data.get('pulse_info', {}).get('count', 0)}")
    
    pulses = data.get('pulse_info', {}).get('pulses', [])
    if pulses:
        print("\nRelated Pulses:")
        for pulse in pulses[:3]:  # Limit to 3 for brevity
            print(f" - {pulse.get('name', 'N/A')} (Created: {pulse.get('created', 'N/A')})")
    else:
        print("\n[-] No related pulses found.")
    print("-" * 50)

# Main function
def main():
    display_banner()
    
    # Get API key from user
    api_key = input("Enter your AlienVault OTX API Key: ").strip()
    if not api_key:
        print("[-] API Key is required. Exiting...")
        sys.exit(1)
    
    while True:
        print("\nThreatIntelHub Menu:")
        print("1. Search by IP Address")
        print("2. Search by Domain")
        print("3. Search by Hash")
        print("4. Exit")
        
        choice = input("Select an option (1-4): ").strip()
        
        if choice == '1':
            indicator = input("Enter IP Address (e.g., 8.8.8.8): ").strip()
            data = fetch_threat_data(api_key, "IPv4", indicator)
            display_threat_data(data)
        
        elif choice == '2':
            indicator = input("Enter Domain (e.g., example.com): ").strip()
            data = fetch_threat_data(api_key, "domain", indicator)
            display_threat_data(data)
        
        elif choice == '3':
            indicator = input("Enter File Hash (e.g., SHA256): ").strip()
            data = fetch_threat_data(api_key, "file", indicator)
            display_threat_data(data)
        
        elif choice == '4':
            print("\n[+] Thank you for using ThreatIntelHub! Stay secure.")
            break
        
        else:
            print("[-] Invalid option. Please try again.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] User interrupted. Exiting gracefully...")
        sys.exit(0)