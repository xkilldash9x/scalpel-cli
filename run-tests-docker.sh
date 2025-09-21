#!/bin/bash
set -e

echo "-- Building test container --"
docker build -t scalpel-browser-tests -f Dockerfile.test .

echo "-- Running tests in container --"
docker run --rm scalpel-browser-tests
