import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Database configuration
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "My_sql@5248!")
    DB_NAME = os.getenv("DB_NAME", "back2school")
    
    # Security
    SECRET_KEY = os.getenv("SECRET_KEY", "secretkey!!")
    
    # Theme colors
    COLOR_PRIMARY = "#89CFF0"  # Baby blue
    COLOR_SECONDARY = "#B5EAD7"  # Pastel green
    COLOR_ACCENT = "#FFD1DC"  # Baby pink