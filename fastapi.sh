#!/bin/bash

SCRIPT_DIR=$(cd $(dirname $0); pwd)
poetry install
poetry run uvicorn app:app --env-file .env --reload