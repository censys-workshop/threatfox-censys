from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings for the application."""

    # Censys Search API ID
    CENSYS_API_ID: str | None = Field(title="Censys Search API ID", default=None)

    # Censys Search API Secret
    CENSYS_API_SECRET: str | None = Field(
        title="Censys Search API Secret", default=None
    )

    # ThreatFox API Key
    THREATFOX_API_KEY: str = Field(title="ThreatFox API Key")

    # Database Config
    DATABASE_URL: str = Field(
        title="Database URL",
    )

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False
    )


settings = Settings()  # type: ignore[call-arg]
