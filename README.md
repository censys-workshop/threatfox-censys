# Threatfox Censys

Threatfox Censys is a tool to query [Censys Search](https://search.censys.io/) for IP addresses and domains and then parses the JSON and submits the results to Threatfox.

## Installation

### Prerequisites

- [Python 3.10](https://www.python.org/downloads/release/python-3100/)
- [A PostgreSQL 15+ Instance](https://www.postgresql.org/)

You will need to install [poetry](https://python-poetry.org/) on Python 3.10.

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

Then install the dependencies.

```bash
poetry install
```

Then you will need to copy the `.env.example` file to `.env` and add your Censys API ID and Secret as well as your Threatfox API key. Also make sure to set the `DATABASE_URL` to your database.

```bash
cp .env.example .env
```

Then you will need to run the database migrations.

```bash
poetry run python -m threatfox_censys --database-migrations
```

## Usage

```bash
poetry run python -m threatfox_censys
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

### Testing

```bash
poetry run pytest
```

### Linting

```bash
poetry run flake8
```

### Formatting

```bash
poetry run black .
poetry run isort .
poetry run pyupgrade --py310-plus threatfox_censys/*.py scripts/*.py
```

## License

Threatfox Censys is licensed under the [MIT](https://choosealicense.com/licenses/mit/) license.

## Author

- [Aidan Holland](mailto:aidan@censys.com)

## Acknowledgements

- [Censys](https://censys.io/)
- [Threatfox](https://threatfox.abuse.ch/)

## TODO

- [ ] Add more fingerprint.
- [ ] Add more tests.
- [ ] Add more documentation.
- [ ] Add better error handling.
<!-- Add your idea here -->
