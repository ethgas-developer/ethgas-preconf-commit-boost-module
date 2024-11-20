#!/bin/bash
set -euo pipefail

docker build -f Dockerfile.ethgas_commit -t ghcr.io/ethgas-developer/commitboost_ethgas_commit:latest .
docker build -f Dockerfile.gen_jwt -t ghcr.io/ethgas-developer/commitboost_gen_jwt:latest .