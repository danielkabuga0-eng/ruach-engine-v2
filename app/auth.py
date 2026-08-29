from fastapi import Header, HTTPException

def verify_api_key(x_api_key: str = Header(None)):
    # Simple placeholder check for enterprise security
    if x_api_key != "ruach-secure-key":
        raise HTTPException(status_code=403, detail="Invalid or missing API Key")
    return x_api_key
