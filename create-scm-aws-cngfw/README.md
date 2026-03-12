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