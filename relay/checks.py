from saas.sdk.app.auth import User
from saas.sdk.app.base import get_current_active_user

from fastapi import Depends


class CheckIfUser:
    def __init__(self, server):
        self.server = server

    async def __call__(self, user: User = Depends(get_current_active_user)):
        pass
