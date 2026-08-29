from fastapi import Depends, HTTPException, status
from .auth import verify_api_key
from .enterprise import has_permission

def require_permission(permission: str):
    async def dependency(account: dict = Depends(verify_api_key)):
        if not has_permission(account, permission):
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"Missing permission: {permission}")
        return account
    return dependency
