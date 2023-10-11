from pydantic import Field, PostgresDsn
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Settings for the application."""

    # Logging Level
    LOGGING_LEVEL: int | str = Field(
        title="Logging Level", env="LOGGING_LEVEL", default="INFO"
    )

    # Censys Search API ID
    CENSYS_API_ID: str | None = Field(
        title="Censys Search API ID", env="CENSYS_API_ID", default=None
    )

    # Censys Search API Secret
    CENSYS_API_SECRET: str | None = Field(
        title="Censys Search API Secret", env="CENSYS_API_SECRET", default=None
    )

    # ThreatFox API Key
    THREATFOX_API_KEY: str = Field(title="ThreatFox API Key", env="THREATFOX_API_KEY")

    # Database Config
    DATABASE_URL: PostgresDsn = Field(
        title="Database URL",
        env="DATABASE_URL",
    )
