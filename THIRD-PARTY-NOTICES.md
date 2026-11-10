# Third-party notices

## Llama Prompt Guard 2 22M (model, distributed as a release asset, not in the git repository)

**Built with Llama.** Goose Web's prompt guard uses Meta's *Llama Prompt Guard 2 22M*
(`meta-llama/Llama-Prompt-Guard-2-22M`, revision `11614a155199674a0a95e6602d6ab0417b790ed0`), converted to ONNX by
`scripts/export-prompt-guard.py` (word embeddings int8). The model is not in the git repository: this project
distributes it as the asset of the GitHub release
[`prompt-guard-2-22m-onnx-1`](https://github.com/GhostNet117/Goose_Web_UI/releases/tag/prompt-guard-2-22m-onnx-1)
(https://github.com/GhostNet117/Goose_Web_UI/releases/download/prompt-guard-2-22m-onnx-1/Llama-Prompt-Guard-2-22M-onnx-int8emb-11614a15.zip, SHA-256 `76d04f9014c82fbf28e51645272c974ca9273ad93512a36b9ef858e4e851eab3`), which the installers download into `<system_dir>/models/prompt-guard-2-22m/`. The package
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
