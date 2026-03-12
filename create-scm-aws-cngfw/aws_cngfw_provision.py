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
    """Enables low-level HTTP debugging to see raw requests and responses."""
    http.client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

def get_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Manage Palo Alto Networks AWS Cloud NGFW via SCM API.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # ---------------------------------------------------------
    # ACTION
    # ---------------------------------------------------------
    parser.add_argument(
        "--action", 
        choices=["create", "read", "update-general", "update-endpoint-management"], 
        default="read",
        help="The action to perform (default: 'read')"
    )

    # ---------------------------------------------------------
    # COMMON ARGUMENTS (Required for all actions)
    # ---------------------------------------------------------
    common = parser.add_argument_group("Common Parameters (Required for all actions)")
    common.add_argument("--tsg", required=True, help="The Tenant Service Group (TSG) ID")
    common.add_argument("--region", required=True, help="Target AWS region (e.g., us-west-2) [Used in query params]")
    
    # ---------------------------------------------------------
    # IDENTIFICATION ARGUMENTS
    # ---------------------------------------------------------
    id_group = parser.add_argument_group("Identification Parameters")
    id_group.add_argument("--fw_id", help="The SCM Firewall ID (e.g., fw-BZT3DZ3MO) [Required for read/update]")
    id_group.add_argument("--name", help="The friendly name of the firewall (applied as an AWS Tag) [Required for create]")

    # ---------------------------------------------------------
    # CONFIGURATION ARGUMENTS (Used for create & update)
    # ---------------------------------------------------------
    config_group = parser.add_argument_group("Configuration Parameters")
    config_group.add_argument("--account", help="AWS Account IDs to allowlist. Can be comma-separated for updates. [Required for create, used in update-endpoint-management]")
    config_group.add_argument("--zones", help="Comma-separated list of Availability Zone IDs [Required for create, used in update-general]")
    config_group.add_argument("--description", help="Description of the firewall [Used in update-general]")

    # ---------------------------------------------------------
    # ADVANCED / OVERRIDES
    # ---------------------------------------------------------
    advanced = parser.add_argument_group("Advanced & Authentication")
    advanced.add_argument("--panw_region", default="americas", help="The PANW control plane region header (default: americas)")
    advanced.add_argument("--client_id", help="OAuth2 Client ID (can also use SCM_CLIENT_ID env var)")
    advanced.add_argument("--debug", action="store_true", help="Enable raw HTTP request/response logging")
    
    args = parser.parse_args()

    # --- Strict Argument Validation Logic ---
    if args.action == "create":
        if not all([args.name, args.account, args.zones]):
            parser.error("--name, --account, and --zones are REQUIRED when --action is 'create'")
    elif args.action in ["read", "update-general", "update-endpoint-management"]:
        if not args.fw_id:
             parser.error(f"--fw_id is REQUIRED when --action is '{args.action}'")
             
    # Specific Update Validations
    if args.action == "update-general" and not (args.zones or args.description):
        parser.error("For 'update-general', you must provide at least --zones or --description to update.")
    if args.action == "update-endpoint-management" and not args.account:
        parser.error("For 'update-endpoint-management', you must provide --account to update.")

    return args

def fetch_bearer_token(tsg_id: str, client_id: str, client_secret: str) -> str:
    """Exchanges Client Credentials for an OAuth2 Access Token."""
    print(f"--- Requesting new access token for TSG {tsg_id} ---")
    payload = {"grant_type": "client_credentials", "scope": f"tsg_id:{tsg_id}"}
    try:
        response = requests.post(AUTH_URL, auth=(client_id, client_secret), data=payload, timeout=15)
        response.raise_for_status()
        return response.json().get("access_token")
    except Exception as e:
        print(f"Authentication Failed: {e}")
        sys.exit(1)

def get_headers(args: argparse.Namespace) -> Dict[str, str]:
    """Determines the best way to get a token and constructs headers."""
    token = os.environ.get("SCM_TOKEN")
    if not token:
        c_id = args.client_id or os.environ.get("SCM_CLIENT_ID")
        c_secret = os.environ.get("SCM_CLIENT_SECRET")
        if c_id and c_secret:
            token = fetch_bearer_token(args.tsg, c_id, c_secret)
        else:
            print("Missing credentials. Please set SCM_CLIENT_SECRET env var.")
            sys.exit(1)

    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "x-panw-region": args.panw_region
    }

def get_tenant_link_id(headers: Dict[str, str]) -> Optional[str]:
    """Fetches the active SCM Link ID required for provisioning."""
    url = f"{BASE_API_URL}/mgmt/tenant"
    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        resp_data = response.json()
        if resp_data.get("ResponseStatus", {}).get("ErrorCode") == 0:
            return resp_data.get("Response", {}).get("ScmInfo", {}).get("LinkId")
        return None
    except Exception:
        return None

def fetch_current_firewall_state(fw_id: str, region: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """Helper function to fetch the current state and optimistic locking tokens."""
    url = f"{BASE_API_URL}/config/ngfirewalls/{fw_id}"
    params = {"region": region}
    print(f"\n[GET] Fetching current state for Firewall '{fw_id}' (needed for UpdateTokens)...")
    try:
        response = requests.get(url, headers=headers, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
        if data.get("ResponseStatus", {}).get("ErrorCode") == 0:
            return data.get("Response", {}).get("Firewall", {})
        else:
             print("[ERROR] Failed to read firewall state.")
             return None
    except Exception as e:
        print(f"[ERROR] Failed to fetch current firewall state: {e}")
        return None

def handle_request(args: argparse.Namespace, headers: Dict[str, str]):
    """Dispatches the appropriate HTTP request based on the requested action."""
    
    # ---------------------------------------------------------
    # ACTION: CREATE
    # ---------------------------------------------------------
    if args.action == "create":
        link_id = get_tenant_link_id(headers)
        if not link_id:
            print("\n[ERROR] Aborting firewall creation due to missing Link ID.")
            sys.exit(1)

        url = f"{BASE_API_URL}/config/ngfirewalls"
        zone_list = [z.strip() for z in args.zones.split(",")]
        payload = {
            "AllowListAccounts": [args.account],
            "Tags": [{"Key": "FirewallName", "Value": args.name}],
            "LinkId": link_id,
            "CustomerZoneIdList": zone_list
        }

        print(f"\n[POST] Provisioning CNGFW: '{args.name}' in {args.region}...")
        try:
            response = requests.post(url, headers=headers, params={"region": args.region}, json=payload, timeout=15)
            response.raise_for_status()
            resp_data = response.json()
            if resp_data.get("ResponseStatus", {}).get("ErrorCode") == 0:
                print(f"\n  -> Success! New Firewall ID: {resp_data.get('Response', {}).get('FirewallId')}")
            else:
                print("\n[ERROR] Payload error:", json.dumps(resp_data, indent=2))
        except Exception as e:
            print(f"\n[ERROR] Create failed: {e}")

    # ---------------------------------------------------------
    # ACTION: READ
    # ---------------------------------------------------------
    elif args.action == "read":
        url = f"{BASE_API_URL}/config/ngfirewalls/{args.fw_id}"
        print(f"\n[GET] Reading configuration for Firewall ID: '{args.fw_id}'...")
        try:
            response = requests.get(url, headers=headers, params={"region": args.region}, timeout=15)
            response.raise_for_status()
            resp_data = response.json()
            if resp_data.get("ResponseStatus", {}).get("ErrorCode") == 0:
                status = resp_data.get("Response", {}).get("Status", {})
                print(f"\n  -> Success! Deployment Status: {status.get('FirewallStatus')}")
                print(json.dumps(resp_data, indent=2))
            else:
                print("\n[ERROR] Payload error:", json.dumps(resp_data, indent=2))
        except Exception as e:
            print(f"\n[ERROR] Read failed: {e}")

    # ---------------------------------------------------------
    # ACTION: UPDATE GENERAL
    # ---------------------------------------------------------
    elif args.action == "update-general":
        current_state = fetch_current_firewall_state(args.fw_id, args.region, headers)
        if not current_state:
            sys.exit(1)

        # Build payload based on capture, persisting existing tokens and tags
        payload = {
            "FirewallId": args.fw_id,
            "Region": args.region,
            "UpdateToken": current_state.get("UpdateToken"),
            "DeploymentUpdateToken": current_state.get("DeploymentUpdateToken"),
            "Tags": current_state.get("Tags", [])
        }
        
        # Apply intended updates
        if args.zones:
            payload["CustomerZoneIdList"] = [z.strip() for z in args.zones.split(",")]
        else:
            payload["CustomerZoneIdList"] = current_state.get("CustomerZoneIdList", [])
            
        if args.description:
            payload["Description"] = args.description
        elif current_state.get("Description"):
            payload["Description"] = current_state.get("Description")

        url = f"{BASE_API_URL}/config/ngfirewalls/{args.fw_id}"
        print(f"\n[PATCH] Applying General Update to Firewall: '{args.fw_id}'...")
        
        try:
            response = requests.patch(url, headers=headers, params={"region": args.region}, json=payload, timeout=15)
            response.raise_for_status()
            print("\n  -> Success! General properties updated.")
            print(json.dumps(response.json(), indent=2))
        except Exception as e:
             print(f"\n[ERROR] Update failed: {e}")
             if 'response' in locals(): print(response.text)

    # ---------------------------------------------------------
    # ACTION: UPDATE ENDPOINT MANAGEMENT
    # ---------------------------------------------------------
    elif args.action == "update-endpoint-management":
        current_state = fetch_current_firewall_state(args.fw_id, args.region, headers)
        if not current_state:
            sys.exit(1)

        # Ensure we pass back the current EndpointServiceName if it exists
        svc_name = current_state.get("EndpointServiceName")
        
        payload = {
            "FirewallId": args.fw_id,
            "Region": args.region,
            "UpdateToken": current_state.get("UpdateToken"),
            "DeploymentUpdateToken": current_state.get("DeploymentUpdateToken"),
            "Endpoints": current_state.get("Endpoints", []),
            "AllowListAccounts": [a.strip() for a in args.account.split(",")]
        }
        
        if svc_name:
            payload["EndpointServiceName"] = svc_name

        url = f"{BASE_API_URL}/config/ngfirewalls/{args.fw_id}"
        print(f"\n[PATCH] Applying Endpoint Management Update to Firewall: '{args.fw_id}'...")
        
        try:
            response = requests.patch(url, headers=headers, params={"region": args.region}, json=payload, timeout=15)
            response.raise_for_status()
            print("\n  -> Success! Endpoint management / Allowlist updated.")
            print(json.dumps(response.json(), indent=2))
        except Exception as e:
             print(f"\n[ERROR] Update failed: {e}")
             if 'response' in locals(): print(response.text)


def main():
    args = get_args()
    if args.debug:
        enable_debug()
    
    headers = get_headers(args)
    handle_request(args, headers)

if __name__ == "__main__":
    main()
