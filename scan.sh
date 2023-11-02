#!/bin/bash

# Navigate to the directory where the script is located
cd "$(dirname "$0")"

# Run the poetry command
poetry run threatfox-censys scan
