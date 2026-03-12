import os
import sys
import json
import argparse
import requests
import http.client
import logging
from typing import Dict, Any, Optional

# --- Constants ---
AUTH_URL = "https://auth.apps.paloaltonetworks.com/am/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com/cngfw-aws/v2"

def enable_debug():
    """
    Enables low-level HTTP debugging to see raw requests and responses.
    """
    http.client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

def get_args():
    """
    Parse command line arguments for AWS CNGFW configuration and authentication.
    """
    parser = argparse.ArgumentParser(description="Provision Palo Alto Networks AWS Cloud NGFW via SCM.")
    
    # Action
    parser.add_argument(
        "--action", 
        choices=["create"], 
        default="create",
        help="The action to perform (currently supports 'create')"
    )

    # Required Firewall Config
    parser.add_argument("--region", required=True, help="Target AWS region (e.g., us-west-2)")
    parser.add_argument("--name", required=True, help="The name of the firewall (applied as an AWS Tag)")
    parser.add_argument("--account", required=True, help="The AWS Account ID to allowlist (e.g., 747599260984)")
    parser.add_argument("--zones", required=True, help="Comma-separated list of Availability Zone IDs (e.g., usw2-az1,usw2-az2)")
    
    # Required SCM Context
    parser.add_argument("--tsg", required=True, help="The Tenant Service Group (TSG) ID")
    parser.add_argument("--panw_region", default="americas", help="The PANW control plane region (default: americas)")
    
    # Authentication Overrides
    parser.add_argument("--client_id", help="OAuth2 Client ID (can also use SCM_CLIENT_ID env var)")
    
    # Debug Flag
    parser.add_argument("--debug", action="store_true", help="Enable raw HTTP request/response logging")
    
    return parser.parse_args()

def fetch_bearer_token(tsg_id: str, client_id: str, client_secret: str) -> str:
    """
    Exchanges Client Credentials for an OAuth2 Access Token.
    """
    print(f"--- Requesting new access token for TSG {tsg_id} ---")
    
    payload = {
        "grant_type": "client_credentials",
        "scope": f"tsg_id:{tsg_id}"
    }
    
    try:
        response = requests.post(AUTH_URL, auth=(client_id, client_secret), data=payload, timeout=15)
        response.raise_for_status()
        token_data = response.json()
        return token_data.get("access_token")
    except requests.exceptions.HTTPError as e:
        print(f"Authentication Failed: {e}")
        if response.status_code == 401:
            print("Check if your Client ID and Client Secret are correct.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during auth: {e}")
        sys.exit(1)

def get_headers(args: argparse.Namespace) -> Dict[str, str]:
    """
    Determines the best way to get a token and constructs headers.
    """
    token = os.environ.get("SCM_TOKEN")
    
    if not token:
        c_id = args.client_id or os.environ.get("SCM_CLIENT_ID")
        c_secret = os.environ.get("SCM_CLIENT_SECRET")
        
        if c_id and c_secret:
            token = fetch_bearer_token(args.tsg, c_id, c_secret)
        else:
            print("Error: No authentication method found.")
            print("Missing credentials. Please set the SCM_CLIENT_SECRET environment variable.")
            print("Usage: export SCM_CLIENT_SECRET='your_secret'")
            sys.exit(1)

    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "x-panw-region": args.panw_region
    }

def get_tenant_link_id(headers: Dict[str, str]) -> Optional[str]:
    """
    Helper function: Fetches the active SCM Link ID required for provisioning.
    """
    url = f"{BASE_API_URL}/mgmt/tenant"
    print("\n[GET] Fetching active Tenant Link ID...")
    
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        resp_data = response.json()
        
        if resp_data.get("ResponseStatus", {}).get("ErrorCode") == 0:
            link_id = resp_data.get("Response", {}).get("ScmInfo", {}).get("LinkId")
            print(f"  -> Found Link ID: {link_id}")
            return link_id
        else:
            print("API responded, but returned an error payload.")
            print(json.dumps(resp_data, indent=2))
            return None
            
    except requests.exceptions.HTTPError as e:
        print(f"Failed to fetch Link ID: {e}")
        print(f"Server Response Body: {response.text}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while fetching Link ID: {e}")
        return None

def handle_request(args: argparse.Namespace, headers: Dict[str, str]):
    """
    Dispatches the appropriate HTTP request based on the requested action.
    """
    if args.action == "create":
        
        # Step 1: We must resolve the Link ID first
        link_id = get_tenant_link_id(headers)
        if not link_id:
            print("\n[ERROR] Aborting firewall creation due to missing Link ID.")
            sys.exit(1)

        # Step 2: Build the creation payload
        url = f"{BASE_API_URL}/config/ngfirewalls"
        params = {"region": args.region}
        
        # Clean up the zones input (handle spaces after commas)
        zone_list = [z.strip() for z in args.zones.split(",")]

        payload = {
            "AllowListAccounts": [args.account],
            "Tags": [
                {
                    "Key": "FirewallName",
                    "Value": args.name
                }
            ],
            "LinkId": link_id,
            "CustomerZoneIdList": zone_list
        }

        print(f"\n[POST] Provisioning CNGFW: '{args.name}' in {args.region}...")
        
        try:
            response = requests.post(url, headers=headers, params=params, json=payload, timeout=15)
            response.raise_for_status()
            resp_data = response.json()
            
            if resp_data.get("ResponseStatus", {}).get("ErrorCode") == 0:
                fw_id = resp_data.get("Response", {}).get("FirewallId")
                print("\n  -> Success! Firewall provisioning initiated.")
                print(f"  -> Your new Firewall ID is: {fw_id}")
                print("\nFull Response:")
                print(json.dumps(resp_data, indent=2))
            else:
                print("\n[ERROR] API responded, but returned an error payload.")
                print(json.dumps(resp_data, indent=2))
                
        except requests.exceptions.HTTPError as e:
            print(f"\n[ERROR] Action '{args.action}' Failed: {e}")
            try:
                print("Server Error Details:", json.dumps(response.json(), indent=2))
            except:
                print(f"Server Response Body: {response.text}")
        except Exception as e:
            print(f"\n[ERROR] An unexpected error occurred: {e}")
            
    else:
        print(f"Action '{args.action}' is not fully implemented in this script yet.")

def main():
    args = get_args()
    if args.debug:
        enable_debug()
    
    headers = get_headers(args)
    handle_request(args, headers)

if __name__ == "__main__":
    main()
