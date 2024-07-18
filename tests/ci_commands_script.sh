#!/usr/bin/env bash

poetry run pytest -vv -s --cov=fence --cov-report xml tests
