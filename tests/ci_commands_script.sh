#!/usr/bin/env bash

poetry run pytest -vv --cov=fence --cov-report xml tests
