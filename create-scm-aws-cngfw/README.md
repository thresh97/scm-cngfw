# SCM AWS Cloud NGFW Provisioning Script

This Python script automates the provisioning of Palo Alto Networks Cloud Next-Generation Firewalls (CNGFW) for AWS using the Strata Cloud Manager (SCM) API. 

It handles OAuth2 authentication, dynamically resolves the required SCM Tenant Link ID, and executes the provisioning payload via the `cngfw-aws/v2` API endpoints.

## ⚠️ Lab & Testing Caveats
**Please read before using in production.**

* **Lab/Proof-of-Concept Use:** This script was developed for lab testing, proof-of-concept (PoC) environments, and educational purposes. 
* **State Management:** This script initiates the `create` action but **does not** poll the API to verify when the firewall has finished deploying, nor does it handle AWS-side routing updates or VPC endpoint attachments.
* **Idempotency:** Running the script multiple times with the same parameters may result in API errors if the firewall name or tags already exist in the target AWS region.
* **Token Expiration:** The script generates short-lived OAuth2 bearer tokens. If you extend this script for long-running batch operations, you will need to implement a token refresh loop.

## Prerequisites

* **Python 3.7+** installed on your system.
* A Palo Alto Networks SCM Service Account with permissions to deploy Cloud NGFW resources.

## Setup & Installation

It is highly recommended to run this script inside a Python virtual environment to prevent dependency conflicts with your system Python packages.

**1. Create a virtual environment:**
Open your terminal and run the following command in the directory where your script is located:
```bash
python3 -m venv venv

```

**2. Activate the virtual environment:**

* **macOS and Linux:**
```bash
source venv/bin/activate

```


* **Windows (Command Prompt):**
```cmd
venv\Scripts\activate.bat

```


* **Windows (PowerShell):**
```powershell
venv\Scripts\Activate.ps1

```



*(You should now see `(venv)` at the beginning of your terminal prompt).*

**3. Install required libraries:**
With the virtual environment active, install the `requests` library:

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

## Usage

```bash
python3 aws_cngfw_provision.py [arguments]

```

### Required Arguments:

| Argument | Description | Example |
| --- | --- | --- |
| `--action` | The CRUD action to perform (currently only `create` is supported). | `--action create` |
| `--tsg` | Your SCM Tenant Service Group (TSG) ID. | `--tsg "1234567890"` |
| `--region` | The target AWS region for the firewall. | `--region us-west-2` |
| `--name` | The name to assign to the firewall (applied as an AWS Tag). | `--name aws-cngfw-us-west-2` |
| `--account` | The 12-digit AWS Account ID where the firewall will be deployed. | `--account 111122223333` |
| `--zones` | A comma-separated list of AWS Availability Zone IDs. | `--zones "usw2-az1,usw2-az2"` |

### Optional Arguments:

* `--panw_region`: The SCM control plane region (Default: `americas`).
* `--debug`: Enables raw low-level HTTP/TLS request and response logging for troubleshooting.

### Example Execution

```bash
python3 aws_cngfw_provision.py \
  --action create \
  --tsg "1234567890" \
  --region us-west-2 \
  --name aws-cngfw-us-west-2 \
  --account 111122223333 \
  --zones "usw2-az1,usw2-az2"

```

When you are finished using the script, you can exit the virtual environment by simply typing `deactivate` in your terminal.

## License & No Warranty

**MIT License**

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

**THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.**

```
