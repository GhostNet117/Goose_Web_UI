# Third-party notices

## Llama Prompt Guard 2 22M (optional model, not in this repository)

**Built with Llama.** Goose Web's prompt guard can use Meta's *Llama Prompt Guard 2 22M*
(`meta-llama/Llama-Prompt-Guard-2-22M`), converted to ONNX by `scripts/export-prompt-guard.py`. The model is not part
of this repository; it is installed separately into `<system_dir>/models/prompt-guard-2-22m/`, and every package
carries the licence (`LICENSE`), the Acceptable Use Policy (`USE_POLICY.md`) and this notice (`NOTICE`):

> Llama 4 is licensed under the Llama 4 Community License, Copyright © Meta Platforms, Inc. All Rights Reserved.

Use of the model is subject to the Llama 4 Community License Agreement (https://www.llama.com/llama4/license/) and the
Llama 4 Acceptable Use Policy (https://www.llama.com/llama4/use-policy/). Anyone who redistributes the package must
keep those files in it and display "Built with Llama".

## Python dependencies

Installed from PyPI with hash-checking (`requirements.lock`), each under its own licence, among them: Starlette,
Uvicorn, websockets, HTTPX, PyYAML, ldap3, python-multipart, cryptography, ONNX Runtime (MIT), Hugging Face
tokenizers (Apache-2.0) and NumPy (BSD-3-Clause), with their dependencies.

## Vendored browser libraries

See `goose_web/static/vendor/README.md`.
