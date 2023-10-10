# Threatfox Censys

Threatfox Censys is a tool to query Censys.io for IP addresses and domains and then parses the JSON and submits the results to Threatfox.

## Installation

You will need to install [poetry](https://python-poetry.org/) on Python 3.10.

```bash
curl -sSL https://install.python-poetry.org | python3 -
```

Then install the dependencies.

```bash
poetry install
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
```

## License

Threatfox Censys is licensed under the [MIT](https://choosealicense.com/licenses/mit/) license.

## Author

- [Aidan Holland](mailto:aidan@censys.com)

## Acknowledgements

- [Censys](https://censys.io/)
- [Threatfox](https://threatfox.abuse.ch/)

## TODO

- [ ] Simplify the virtual hosts arg in the fingerprint model.
- [ ] Add more fingerprint models.
- [ ] Add more tests.
- [ ] Add more documentation.
- [ ] Add more error handling.
- [ ] Add more logging.
