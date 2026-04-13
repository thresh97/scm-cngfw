import os
import sys
import re
import json
import argparse
import requests
import http.client
import logging
from typing import Dict, Any, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- Constants ---
AUTH_URL = "https://auth.apps.paloaltonetworks.com/am/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com/cngfw-aws/v2"

AWS_ACCOUNT_ID_RE = re.compile(r'^\d{12}$')
ZONE_ID_RE = re.compile(r'^[a-z0-9]+-az\d+$')
FW_ID_RE = re.compile(r'^fw-[A-Z0-9]+$')


def enable_debug():
    """Enables low-level HTTP debugging to see raw requests and responses."""
    http.client.HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


def _make_session() -> requests.Session:
    """Creates a requests Session with retry logic for transient failures."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PATCH"]
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def _handle_http_error(e: requests.exceptions.HTTPError, fw_id: Optional[str] = None) -> None:
    """Prints a context-aware error message for common HTTP error codes."""
    status = e.response.status_code
    if status == 401:
        print("[ERROR] Authentication failed (401). Check your credentials or token expiry.")
    elif status == 404:
        target = f"Firewall '{fw_id}'" if fw_id else "Resource"
        print(f"[ERROR] {target} not found (404). Verify the ID and region.")
    elif status == 409:
        print("[ERROR] Conflict (409): another update may be in progress. Fetch the latest state and retry.")
    elif status == 429:
        print("[ERROR] Rate limited (429). Retry after a short delay.")
    else:
        print(f"[ERROR] HTTP {status}: {e.response.text}")


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
    config_group.add_argument("--account", help="Comma-separated AWS Account IDs to allowlist. [Required for create, used in update-endpoint-management]")
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


def validate_inputs(args: argparse.Namespace) -> None:
    """Validates argument values and exits on invalid input."""
    errors = []
    if args.account:
        for acct in [a.strip() for a in args.account.split(",")]:
            if not AWS_ACCOUNT_ID_RE.match(acct):
                errors.append(f"Invalid AWS Account ID '{acct}' — must be exactly 12 digits.")
    if args.zones:
        for zone in [z.strip() for z in args.zones.split(",")]:
            if not ZONE_ID_RE.match(zone):
                errors.append(f"Invalid Zone ID '{zone}' — expected format like 'usw2-az1'.")
    if args.fw_id and not FW_ID_RE.match(args.fw_id):
        errors.append(f"Invalid Firewall ID '{args.fw_id}' — expected format like 'fw-BZT3DZ3MO'.")
    if errors:
        for err in errors:
            print(f"[ERROR] {err}")
        sys.exit(1)


def fetch_bearer_token(tsg_id: str, client_id: str, client_secret: str, session: requests.Session) -> str:
    """Exchanges Client Credentials for an OAuth2 Access Token."""
    print(f"--- Requesting new access token for TSG {tsg_id} ---")
    payload = {"grant_type": "client_credentials", "scope": f"tsg_id:{tsg_id}"}
    try:
        response = session.post(AUTH_URL, auth=(client_id, client_secret), data=payload, timeout=15)
        response.raise_for_status()
        return response.json().get("access_token")
    except requests.exceptions.HTTPError as e:
        _handle_http_error(e)
        sys.exit(1)
    except requests.exceptions.Timeout:
        print("[ERROR] Authentication request timed out.")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Authentication failed: {e}")
        sys.exit(1)


def get_headers(args: argparse.Namespace, session: requests.Session) -> Dict[str, str]:
    """Determines the best way to get a token and constructs headers."""
    token = os.environ.get("SCM_TOKEN")
    if not token:
        c_id = args.client_id or os.environ.get("SCM_CLIENT_ID")
        c_secret = os.environ.get("SCM_CLIENT_SECRET")
        if c_id and c_secret:
            token = fetch_bearer_token(args.tsg, c_id, c_secret, session)
        else:
            print("[ERROR] Missing credentials. Set SCM_CLIENT_ID and SCM_CLIENT_SECRET env vars, or SCM_TOKEN.")
            sys.exit(1)

    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "x-panw-region": args.panw_region
    }


def get_tenant_link_id(headers: Dict[str, str], session: requests.Session) -> Optional[str]:
    """Fetches the active SCM Link ID required for provisioning."""
    url = f"{BASE_API_URL}/mgmt/tenant"
    try:
        response = session.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        resp_data = response.json()
        if resp_data.get("ResponseStatus", {}).get("ErrorCode") == 0:
            return resp_data.get("Response", {}).get("ScmInfo", {}).get("LinkId")
        print(f"[ERROR] Unexpected response fetching Link ID: {resp_data.get('ResponseStatus')}")
        return None
    except requests.exceptions.HTTPError as e:
        print("[ERROR] Failed to fetch Link ID:")
        _handle_http_error(e)
        return None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch Link ID: {e}")
        return None


def fetch_current_firewall_state(fw_id: str, region: str, headers: Dict[str, str], session: requests.Session) -> Optional[Dict[str, Any]]:
    """Helper function to fetch the current state and optimistic locking tokens."""
    url = f"{BASE_API_URL}/config/ngfirewalls/{fw_id}"
    print(f"\n[GET] Fetching current state for Firewall '{fw_id}' (needed for UpdateTokens)...")
    try:
        response = session.get(url, headers=headers, params={"region": region}, timeout=15)
        response.raise_for_status()
        data = response.json()
        if data.get("ResponseStatus", {}).get("ErrorCode") == 0:
            return data.get("Response", {}).get("Firewall", {})
        print("[ERROR] Failed to read firewall state.")
        return None
    except requests.exceptions.HTTPError as e:
        _handle_http_error(e, fw_id)
        return None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to fetch current firewall state: {e}")
        return None


def handle_request(args: argparse.Namespace, headers: Dict[str, str], session: requests.Session):
    """Dispatches the appropriate HTTP request based on the requested action."""

    # ---------------------------------------------------------
    # ACTION: CREATE
    # ---------------------------------------------------------
    if args.action == "create":
        link_id = get_tenant_link_id(headers, session)
        if not link_id:
            print("\n[ERROR] Aborting firewall creation due to missing Link ID.")
            sys.exit(1)

        url = f"{BASE_API_URL}/config/ngfirewalls"
        account_list = [a.strip() for a in args.account.split(",")]
        zone_list = [z.strip() for z in args.zones.split(",")]
        payload = {
            "AllowListAccounts": account_list,
            "Tags": [{"Key": "FirewallName", "Value": args.name}],
            "LinkId": link_id,
            "CustomerZoneIdList": zone_list
        }

        print(f"\n[POST] Provisioning CNGFW: '{args.name}' in {args.region}...")
        try:
            response = session.post(url, headers=headers, params={"region": args.region}, json=payload, timeout=15)
            response.raise_for_status()
            resp_data = response.json()
            if resp_data.get("ResponseStatus", {}).get("ErrorCode") == 0:
                print(f"\n  -> Success! New Firewall ID: {resp_data.get('Response', {}).get('FirewallId')}")
            else:
                print("\n[ERROR] Payload error:", json.dumps(resp_data, indent=2))
        except requests.exceptions.HTTPError as e:
            _handle_http_error(e)
        except requests.exceptions.Timeout:
            print("\n[ERROR] Request timed out.")
        except requests.exceptions.RequestException as e:
            print(f"\n[ERROR] Create failed: {e}")

    # ---------------------------------------------------------
    # ACTION: READ
    # ---------------------------------------------------------
    elif args.action == "read":
        url = f"{BASE_API_URL}/config/ngfirewalls/{args.fw_id}"
        print(f"\n[GET] Reading configuration for Firewall ID: '{args.fw_id}'...")
        try:
            response = session.get(url, headers=headers, params={"region": args.region}, timeout=15)
            response.raise_for_status()
            resp_data = response.json()
            if resp_data.get("ResponseStatus", {}).get("ErrorCode") == 0:
                status = resp_data.get("Response", {}).get("Status", {})
                print(f"\n  -> Success! Deployment Status: {status.get('FirewallStatus')}")
                print(json.dumps(resp_data, indent=2))
            else:
                print("\n[ERROR] Payload error:", json.dumps(resp_data, indent=2))
        except requests.exceptions.HTTPError as e:
            _handle_http_error(e, args.fw_id)
        except requests.exceptions.Timeout:
            print("\n[ERROR] Request timed out.")
        except requests.exceptions.RequestException as e:
            print(f"\n[ERROR] Read failed: {e}")

    # ---------------------------------------------------------
    # ACTION: UPDATE GENERAL
    # ---------------------------------------------------------
    elif args.action == "update-general":
        current_state = fetch_current_firewall_state(args.fw_id, args.region, headers, session)
        if not current_state:
            sys.exit(1)

        # Persist all existing state; only override what was explicitly requested
        payload = {
            "FirewallId": args.fw_id,
            "Region": args.region,
            "UpdateToken": current_state.get("UpdateToken"),
            "DeploymentUpdateToken": current_state.get("DeploymentUpdateToken"),
            "LinkId": current_state.get("LinkId"),
            "AllowListAccounts": current_state.get("AllowListAccounts", []),
            "Tags": current_state.get("Tags", []),
            "CustomerZoneIdList": [z.strip() for z in args.zones.split(",")] if args.zones
                                  else current_state.get("CustomerZoneIdList", []),
        }

        if args.description:
            payload["Description"] = args.description
        elif current_state.get("Description"):
            payload["Description"] = current_state.get("Description")

        url = f"{BASE_API_URL}/config/ngfirewalls/{args.fw_id}"
        print(f"\n[PATCH] Applying General Update to Firewall: '{args.fw_id}'...")

        try:
            response = session.patch(url, headers=headers, params={"region": args.region}, json=payload, timeout=15)
            response.raise_for_status()
            print("\n  -> Success! General properties updated.")
            print(json.dumps(response.json(), indent=2))
        except requests.exceptions.HTTPError as e:
            _handle_http_error(e, args.fw_id)
        except requests.exceptions.Timeout:
            print("\n[ERROR] Request timed out.")
        except requests.exceptions.RequestException as e:
            print(f"\n[ERROR] Update failed: {e}")

    # ---------------------------------------------------------
    # ACTION: UPDATE ENDPOINT MANAGEMENT
    # ---------------------------------------------------------
    elif args.action == "update-endpoint-management":
        current_state = fetch_current_firewall_state(args.fw_id, args.region, headers, session)
        if not current_state:
            sys.exit(1)

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
            response = session.patch(url, headers=headers, params={"region": args.region}, json=payload, timeout=15)
            response.raise_for_status()
            print("\n  -> Success! Endpoint management / Allowlist updated.")
            print(json.dumps(response.json(), indent=2))
        except requests.exceptions.HTTPError as e:
            _handle_http_error(e, args.fw_id)
        except requests.exceptions.Timeout:
            print("\n[ERROR] Request timed out.")
        except requests.exceptions.RequestException as e:
            print(f"\n[ERROR] Update failed: {e}")


def main():
    args = get_args()
    if args.debug:
        enable_debug()
    validate_inputs(args)
    session = _make_session()
    headers = get_headers(args, session)
    handle_request(args, headers, session)


if __name__ == "__main__":
    main()
