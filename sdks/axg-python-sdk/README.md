# AXG Python SDK

Official Python SDK for **Agent Execution Guard (AXG)**.

This SDK provides utilities to verify AXG Passport tokens (RS256 JWT) in your backend services.

## Installation

```bash
pip install axg-python-sdk
```

## Usage

```python
import asyncio
from axg_python_sdk import AxgClient

async def main():
    axg = AxgClient("https://axg.your-domain.com")
    
    token = "..."  # The Passport token from AXG
    payload = {"merchant": "UBER", "amount": 15}  # Data to verify

    try:
        claims = await axg.verify_passport(
            token=token, 
            payload=payload, 
            app_id="your-app-id"
        )
        print(f"Authorized action: {claims['action_type']}")
    except Exception as e:
        print(f"Verification failed: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())
```
