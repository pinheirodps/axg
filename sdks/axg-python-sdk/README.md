# AXG Python SDK

Official Python SDK for **Agent Execution Guard (AXG)**.

This SDK provides utilities to verify AXG Passport tokens (RS256 JWT) in your backend services.

## Installation

```bash
pip install axg-python-sdk
```

## Usage

```python
from axg_python_sdk import verify_passport

public_key = '...' # Your AXG Public Key
token = '...' # The token from AXG

try:
    payload = verify_passport(token, public_key)
    print(f"Authorized action: {payload['action']}")
except Exception as e:
    print(f"Unauthorized: {str(e)}")
```
