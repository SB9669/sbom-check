# SBOM Check

Free SBOM completeness check that runs entirely in your browser, plus an open verifier for signed evidence reports.

- `index.html`: the free checker (CycloneDX / SPDX JSON). Your file never leaves your machine.
- `verify.py`: open-source verifier for evidence bundles (`pip install cryptography`).
- `samples/`: a real signed evidence bundle and report for a flawed SBOM and for a complete one.

    python verify.py samples/evidence-demo.json --sbom samples/demo.cdx.json --fingerprint 8DC1CCF8C3052039

Without `--fingerprint`, verification shows a file was not altered, not who signed it. Pin the key you trust.

## What this is not
An evidence aid, not a certification. No guarantee of FDA, EU or DoD acceptance; not legal or regulatory advice.
Completeness follows the NTIA 2021 minimum elements. The CISA 2025 draft additions are shown separately; confirm against CISA's current publication.
Vulnerability data comes from the public OSV.dev database and can miss issues, especially in firmware or vendored code without a package URL.

## Signed evidence reports
The report generator is not part of this repository. Signed reports are produced as a paid service (see the site).

Contact: selfbrandedsupport@gmail.com

License: MIT for the files in this repository.
