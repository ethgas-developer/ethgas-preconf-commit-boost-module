#!/bin/bash
set -euo pipefail

docker buildx build --pull --no-cache-filter chef,runtime --load -f Dockerfile.ethgas_commit -t ghcr.io/ethgas-developer/commitboost_ethgas_commit:latest .
docker buildx build --pull --no-cache-filter chef,runtime --load -f Dockerfile.ethgas_deposit -t ghcr.io/ethgas-developer/commitboost_ethgas_deposit:latest .
docker buildx build --pull --no-cache-filter chef,runtime --load -f Dockerfile.gen_jwt -t ghcr.io/ethgas-developer/commitboost_gen_jwt:latest .
