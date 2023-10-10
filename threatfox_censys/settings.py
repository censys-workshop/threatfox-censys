from pathlib import Path

from pydantic import Field, PostgresDsn, RedisDsn
from pydantic_settings import BaseSettings

current_dir = Path(__file__).parent
DEFAULT_DATA_DIRECTORY = current_dir / "data"
SEARCH_DSL_DIRECTORY = DEFAULT_DATA_DIRECTORY / "censys_search_dsl"
SEARCH_QUERY_DIRECTORY = DEFAULT_DATA_DIRECTORY / "censys_search_queries"
SHODAN_SEARCH_QUERY_DIRECTORY = DEFAULT_DATA_DIRECTORY / "shodan_search_queries"


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

    # Database Config
    DATABASE_URL: PostgresDsn = Field(
        title="Database URL",
        env="DATABASE_URL",
    )

    # Redis Config
    REDIS_URL: RedisDsn | None = Field(
        title="Redis URL",
        env="REDIS_URL",
        default=None,
    )
    REDIS_PASSWORD: str | None = Field(
        title="Redis Password",
        env="REDIS_PASSWORD",
        default=None,
    )
