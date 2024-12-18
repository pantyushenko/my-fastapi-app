import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("postgresql://user:password@localhost:5432/mydatabase")
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "secret")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
