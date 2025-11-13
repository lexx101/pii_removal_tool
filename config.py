import os
from pathlib import Path

class Config:
    """Application configuration."""

    # Base directory
    BASE_DIR = Path(__file__).parent

    # Data directory for JSON files
    DATA_DIR = os.getenv('DATA_DIR', os.path.join(BASE_DIR, 'data'))

    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('DEBUG', 'False').lower() in ('true', '1', 't')
    PORT = int(os.getenv('PORT', 5000))

    # Security settings
    JSON_SORT_KEYS = False
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max request size

    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
