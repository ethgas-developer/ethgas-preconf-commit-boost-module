#!/usr/bin/env python3
"""Gate TLS/crypto advisories while retaining the complete RustSec report."""
import json
import sys

with open(sys.argv[1], encoding="utf-8") as report:
    audit = json.load(report)
# --no-fetch omits commit metadata even for a successfully loaded database.
if audit["database"]["advisory-count"] < 1:
    raise SystemExit("The RustSec advisory database was not loaded")

packages = {
    "rustls", "rustls-webpki", "webpki-roots", "webpki-root-certs",
    "rustls-platform-verifier", "rustls-native-certs", "native-tls",
    "openssl", "openssl-sys", "openssl-src", "aws-lc-rs", "aws-lc-sys", "ring",
}
failures = []
for finding in audit["vulnerabilities"]["list"]:
    package = finding["package"]
    advisory = finding["advisory"]
    summary = f'{advisory["id"]}: {package["name"]} {package["version"]}: {advisory["title"]}'
    if package["name"] in packages:
        failures.append(summary)
    else:
        print(f"Additional dependency finding outside the TLS gate: {summary}")
if failures:
    raise SystemExit("\n".join(failures))
print("No known TLS/crypto vulnerabilities in the locked dependencies.")
