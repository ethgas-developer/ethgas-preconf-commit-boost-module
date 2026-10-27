#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
image=${1:?image reference required}
revision=${2:?source revision required}

for platform in linux/amd64 linux/arm64; do
  docker pull --platform "$platform" "$image"
  actual=$(docker image inspect "$image" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
  test "$actual" = "$revision"
  docker run --rm --platform "$platform" --network none \
    --entrypoint /bin/sh \
    --mount "type=bind,source=$PWD/scripts/check-ca-trust.sh,target=/tmp/check-ca-trust.sh,readonly" \
    --mount "type=bind,source=$PWD/tests/data/emudhra,target=/tmp/emudhra,readonly" \
    "$image" -ec '
      sh /tmp/check-ca-trust.sh /tmp/emudhra
      found=0
      for binary in /usr/local/bin/ethgas_commit /usr/local/bin/ethgas_deposit /usr/local/bin/gen_jwt; do
        if test -x "$binary"; then
          found=$((found + 1))
          ldd "$binary" > /tmp/libraries.txt
          cat /tmp/libraries.txt
          if grep -q "not found" /tmp/libraries.txt; then exit 1; fi
          if test "${binary##*/}" = gen_jwt; then
            cd /tmp
            CB_MODULE_ID=ETHGAS_COMMIT "$binary"
            test -s .cb.env
            grep -q "^CB_SIGNER_JWT=" .cb.env
          else
            if CB_CONFIG=/tmp/ethgas-release-no-config.toml CB_MODULE_ID=ETHGAS_COMMIT "$binary" > /tmp/startup.txt 2>&1; then
              cat /tmp/startup.txt
              exit 1
            fi
            grep -q "ethgas-release-no-config.toml" /tmp/startup.txt
          fi
        fi
      done
      test "$found" -eq 1
    '
  echo "$image $platform: runtime trust, source revision, linkage, and startup verified"
done
