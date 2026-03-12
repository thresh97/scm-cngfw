# SCM AWS Cloud NGFW Management Script

This Python script automates the provisioning and management of Palo Alto Networks Cloud Next-Generation Firewalls (CNGFW) for AWS using the Strata Cloud Manager (SCM) API. 

It handles OAuth2 authentication, dynamically resolves SCM Tenant Link IDs, manages optimistic locking tokens (UpdateTokens) under the hood, and executes payloads via the `cngfw-aws/v2` API endpoints.

## ⚠️ Lab & Testing Caveats
**Please read before using in production.**

* **Lab/Proof-of-Concept Use:** This script was developed for lab testing, proof-of-concept (PoC) environments, and educational purposes. 
* **State Management:** This script initiates API actions but **does not** poll to verify when a firewall has finished its AWS-side deployment, nor does it handle AWS routing updates or VPC endpoint attachments.
* **Concurrency:** The `update` actions automatically fetch the latest `UpdateToken` and `DeploymentUpdateToken` before patching. If another administrator modifies the firewall milliseconds before your script executes, the API will reject the payload to prevent accidental overwrites.
* **Token Expiration:** The script generates short-lived OAuth2 bearer tokens. If you extend this script for long-running batch operations, you will need to implement a token refresh loop.

## Prerequisites

* **Python 3.7+** installed on your system.
* A Palo Alto Networks SCM Service Account with permissions to manage Cloud NGFW resources.

## Setup & Installation

It is highly recommended to run this script inside a Python virtual environment to prevent dependency conflicts with your system Python packages.

**1. Create a virtual environment:**
```bash
python3 -m venv venv

```

**2. Activate the virtual environment:**

* **macOS and Linux:** `source venv/bin/activate`
* **Windows (Cmd):** `venv\Scripts\activate.bat`
* **Windows (PowerShell):** `venv\Scripts\Activate.ps1`

**3. Install required libraries:**

```bash
pip install requests

```

## Authentication

The script requires an SCM OAuth2 Client ID and Client Secret. To prevent hardcoding credentials in the script or leaving them in your bash history, export them as environment variables before running:

**macOS / Linux:**

```bash
export SCM_CLIENT_ID="your_service_account_client_id"
export SCM_CLIENT_SECRET="your_service_account_secret"

```

**Windows (PowerShell):**

```powershell
$env:SCM_CLIENT_ID="your_service_account_client_id"
$env:SCM_CLIENT_SECRET="your_service_account_secret"

```

## Usage & Arguments

```bash
python3 aws_cngfw_provision.py --action <ACTION> [arguments]

```

### Supported Actions:

* `create`: Provisions a new firewall.
* `read`: Retrieves the current configuration and deployment status of a firewall.
* `update-general`: Modifies the Availability Zones or Description.
* `update-endpoint-management`: Modifies the allowlisted AWS accounts for Endpoint access.

### Argument Reference:

| Argument | Description | Used In |
| --- | --- | --- |
| **`--action`** | The operation to perform. | *All* |
| **`--tsg`** | Your SCM Tenant Service Group (TSG) ID. | *All (Required)* |
| **`--region`** | The target AWS region (e.g., `us-west-2`). | *All (Required)* |
| **`--fw_id`** | The SCM-generated Firewall ID (e.g., `fw-BZT3DZ3MO`). | `read`, `update-*` |
| **`--name`** | The friendly name of the firewall (applied as an AWS Tag). | `create` |
| **`--account`** | AWS Account IDs to allowlist. Comma-separate for multiple. | `create`, `update-endpoint-management` |
| **`--zones`** | Comma-separated list of AWS Availability Zone IDs. | `create`, `update-general` |
| **`--description`** | A text description for the firewall. | `update-general` |
| **`--panw_region`** | SCM control plane region (Default: `americas`). | *Optional* |
| **`--debug`** | Enables raw HTTP/TLS request logging for troubleshooting. | *Optional* |

---

## Examples

### 1. Create a Firewall

Requires `--name`, `--account`, and `--zones`.

```bash
python3 aws_cngfw_provision.py \
  --action create \
  --tsg "1234567890" \
  --region us-west-2 \
  --name aws-cngfw-us-west-2 \
  --account 111122223333 \
  --zones "usw2-az1,usw2-az2"

```

### 2. Read Firewall Status

Requires `--fw_id`.

```bash
python3 aws_cngfw_provision.py \
  --action read \
  --tsg "1234567890" \
  --region us-west-2 \
  --fw_id "fw-BZT3DZ3MO"

```

### 3. Update General Settings (Zones/Description)

Requires `--fw_id` and at least one of `--zones` or `--description`.

```bash
python3 aws_cngfw_provision.py \
  --action update-general \
  --tsg "1234567890" \
  --region us-west-2 \
  --fw_id "fw-BZT3DZ3MO" \
  --description "Updated via API script" \
  --zones "usw2-az1,usw2-az2,usw2-az3"

```

### 4. Update Endpoint Management (Allowlist)

Requires `--fw_id` and `--account`. You can pass multiple accounts by comma-separating them.

```bash
python3 aws_cngfw_provision.py \
  --action update-endpoint-management \
  --tsg "1234567890" \
  --region us-west-2 \
  --fw_id "fw-BZT3DZ3MO" \
  --account "111122223333,444455556666"

```

---

## License & No Warranty

**MIT License**

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

```
