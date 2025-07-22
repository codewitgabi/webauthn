from pydantic import BaseModel
from typing import List, Optional
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Credential(BaseModel):
    credential_id: bytes
    public_key: bytes
    counter: int


class User(BaseModel):
    email: str
    password: Optional[str] = None
    credentials: List[Credential] = []

    def set_password(self, password: str):
        self.password = pwd_context.hash(password)

    def verify_password(self, password: str) -> bool:
        return pwd_context.verify(password, self.password) if self.password else False
