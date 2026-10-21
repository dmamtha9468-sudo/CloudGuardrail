# CloudGuardrail

CloudGuardrail checks deployment configuration for common security risks before it ships. The browser UI calls a local FastAPI service; submitted text is analyzed in memory and is not written to disk or sent to a cloud service.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Open <http://127.0.0.1:8000>. The API docs are at <http://127.0.0.1:8000/docs>.

## What it checks

- **Dockerfiles:** root runtime user, unpinned base image, sensitive exposed ports, credentials in `ENV`/`ARG`, and downloaded scripts piped directly into a shell.
- **Kubernetes YAML:** pod host networking, `hostPath` volumes, non-root enforcement, privileged containers, privilege escalation, unpinned images, missing resource limits, and externally exposed LoadBalancer services.
- **Terraform HCL:** public S3 ACLs, world-open security group ingress, publicly reachable or unencrypted RDS instances, and wildcard IAM actions.
- **JSON:** parse errors and values that resemble hard-coded credentials.

Every finding includes a stable rule ID, severity, explanation, and suggested fix. `POST /api/scan` accepts `{ "filename", "content", "file_type" }`; `file_type` may be `auto`, `dockerfile`, `kubernetes`, `terraform`, or `json`.

## Run tests

```bash
python -m unittest discover -v
```

## Run in Docker

```bash
docker build -t cloudguardrail .
docker run --rm -p 8000:8000 cloudguardrail
```

## Scope and limits

This is a deterministic rule-based scanner, not a complete cloud security audit. It does not execute configuration, contact cloud accounts, validate runtime state, or understand every valid configuration pattern. YAML and Terraform are parsed before checks run, but some checks are intentionally conservative heuristics. Review results in the context of your deployment and use a mature scanner and policy engine for production assurance.
