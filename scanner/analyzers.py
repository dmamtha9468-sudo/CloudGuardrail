"""Deterministic, local analyzers for common deployment configuration risks."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from typing import Any

import hcl2
import yaml


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    file: str
    line: int | None
    detail: str
    fix: str
    category: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _line_for(content: str, pattern: str) -> int | None:
    regex = re.compile(pattern, re.IGNORECASE)
    for idx, line in enumerate(content.splitlines(), start=1):
        if regex.search(line):
            return idx
    return None


def _finding(rule_id: str, severity: str, title: str, filename: str,
             line: int | None, detail: str, fix: str, category: str) -> Finding:
    return Finding(rule_id, severity, title, filename, line, detail, fix, category)


def _dockerfile(content: str, filename: str) -> list[Finding]:
    findings: list[Finding] = []
    lines = content.splitlines()
    joined = "\n".join(lines)

    if _line_for(joined, r"^\s*USER\s+root\b"):
        findings.append(_finding("DOCKER-001", "high", "Container runs as root", filename,
            _line_for(joined, r"^\s*USER\s+root\b"),
            "The image explicitly selects root for its runtime user, increasing the impact of a compromised process.",
            "Create a dedicated unprivileged user and set USER to that account for the final image stage.", "container"))
    unpinned_base_line = None
    for idx, line in enumerate(lines, start=1):
        match = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?([^\s]+)", line, re.I)
        if match:
            image = match.group(1).lower()
            if image != "scratch" and "@sha256:" not in image:
                image_name = image.rsplit("/", 1)[-1]
                if ":" not in image_name or image_name.endswith(":latest"):
                    unpinned_base_line = idx
                    break
    if unpinned_base_line:
        findings.append(_finding("DOCKER-002", "medium", "Base image is not pinned", filename,
            unpinned_base_line,
            "A moving image tag can change between builds, making deployments harder to reproduce and review.",
            "Pin the base image to a specific version or immutable digest.", "supply-chain"))
    if _line_for(joined, r"^\s*EXPOSE\s+(?:22|2375|2376|3306|5432|6379|9200)\b"):
        findings.append(_finding("DOCKER-003", "medium", "Sensitive service port exposed", filename,
            _line_for(joined, r"^\s*EXPOSE\s+(?:22|2375|2376|3306|5432|6379|9200)\b"),
            "The image documents a commonly sensitive management or data-service port.",
            "Remove the port if it is not required, and restrict network access at the deployment layer.", "network"))
    if _line_for(joined, r"^\s*(?:ENV|ARG)\s+[^\n]*(?:password|secret|token|api[_-]?key|access[_-]?key)\s*="):
        findings.append(_finding("DOCKER-004", "high", "Possible credential in build configuration", filename,
            _line_for(joined, r"^\s*(?:ENV|ARG)\s+[^\n]*(?:password|secret|token|api[_-]?key|access[_-]?key)\s*="),
            "Build arguments and image environment values can be preserved in image metadata or build history.",
            "Rotate any real credential and inject secrets at runtime through a managed secret store.", "secrets"))
    if _line_for(joined, r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash)\b"):
        findings.append(_finding("DOCKER-005", "medium", "Remote script piped to a shell", filename,
            _line_for(joined, r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash)\b"),
            "The build executes downloaded content directly, without a visible integrity check.",
            "Pin the source to a verified release, validate its checksum or signature, then execute it.", "supply-chain"))
    if not any(re.match(r"^\s*USER\s+", line, re.I) for line in lines):
        findings.append(_finding("DOCKER-006", "low", "No runtime user declared", filename, None,
            "No USER instruction is present. The effective user depends on the base image and build stage.",
            "Declare an unprivileged runtime user explicitly in the final build stage.", "container"))
    return findings


def _yaml_documents(content: str, filename: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        documents = list(yaml.safe_load_all(content))
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark else None
        findings.append(_finding("YAML-000", "low", "Could not parse YAML", filename, line,
            "This file has a YAML syntax issue, so structural checks could not run.",
            "Fix the YAML syntax and scan again. The scanner does not execute the manifest.", "validation"))
        return findings

    def scan_pod_spec(spec: Any, base_line: int | None) -> None:
        if not isinstance(spec, dict):
            return
        pod_sc = spec.get("securityContext") or {}
        if not isinstance(pod_sc, dict):
            pod_sc = {}
        if spec.get("hostNetwork") is True:
            findings.append(_finding("K8S-002", "high", "Pod shares the host network", filename, None,
                "hostNetwork gives the pod access to the node network namespace and can bypass normal network isolation.",
                "Remove hostNetwork unless it is essential; apply a documented exception and node-level controls if required.", "network"))
        volumes = spec.get("volumes") or []
        if any(isinstance(v, dict) and "hostPath" in v for v in volumes):
            findings.append(_finding("K8S-003", "high", "Host filesystem path mounted", filename, None,
                "A hostPath volume exposes a node filesystem path to the workload.",
                "Use a managed volume type. If hostPath is required, mount a specific read-only path and constrain the workload.", "filesystem"))
        containers = list(spec.get("containers") or []) + list(spec.get("initContainers") or [])
        for container in containers:
            if not isinstance(container, dict):
                continue
            name = container.get("name", "container")
            image = str(container.get("image", ""))
            sc = container.get("securityContext") or {}
            if not isinstance(sc, dict):
                sc = {}
            if sc.get("runAsNonRoot") is False or (
                pod_sc.get("runAsNonRoot") is not True and sc.get("runAsNonRoot") is not True
            ):
                findings.append(_finding("K8S-001", "medium", f"Workload does not require a non-root user ({name})", filename, None,
                    "Neither the pod nor this container security context enforces runAsNonRoot.",
                    "Set runAsNonRoot: true at pod or container level and define a non-root runAsUser where needed.", "container"))
            if image.endswith(":latest") or (image and ":" not in image.rsplit("/", 1)[-1] and "@sha256:" not in image):
                findings.append(_finding("K8S-004", "medium", f"Image is not pinned ({name})", filename, None,
                    f"Container {name} uses a mutable tag or no explicit version.",
                    "Pin the image to a reviewed version or immutable digest.", "supply-chain"))
            if sc.get("privileged") is True:
                findings.append(_finding("K8S-005", "high", f"Privileged container ({name})", filename, None,
                    "Privileged mode grants broad host-level capabilities and weakens container isolation.",
                    "Remove privileged mode and grant only specific capabilities required by the workload.", "container"))
            if sc.get("allowPrivilegeEscalation") is not False:
                findings.append(_finding("K8S-006", "medium", f"Privilege escalation not disabled ({name})", filename, None,
                    "The container does not explicitly prevent a process from gaining additional privileges.",
                    "Set securityContext.allowPrivilegeEscalation: false.", "container"))
            if not (container.get("resources") or {}).get("limits"):
                findings.append(_finding("K8S-007", "low", f"Resource limits missing ({name})", filename, None,
                    "Without resource limits, this container can consume more node resources than intended.",
                    "Set realistic CPU and memory limits based on observed workload needs.", "availability"))

    for doc in documents:
        if not isinstance(doc, dict):
            continue
        kind = str(doc.get("kind", "")).lower()
        spec = doc.get("spec") or {}
        if not isinstance(spec, dict):
            continue
        if kind == "pod":
            scan_pod_spec(spec, 1)
        elif kind in {"deployment", "statefulset", "daemonset", "job", "replicaset"}:
            template = spec.get("template") or {}
            if isinstance(template, dict):
                scan_pod_spec(template.get("spec") or {}, None)
        elif kind == "cronjob":
            job_template = spec.get("jobTemplate") or {}
            job_spec = job_template.get("spec", {}) if isinstance(job_template, dict) else {}
            pod_template = job_spec.get("template", {}) if isinstance(job_spec, dict) else {}
            if isinstance(pod_template, dict):
                scan_pod_spec(pod_template.get("spec") or {}, None)
        elif kind == "service" and str(spec.get("type", "")).lower() == "loadbalancer":
            # Public exposure is an operational decision; report it as a low-risk review item.
            findings.append(_finding("K8S-008", "low", "LoadBalancer service exposes an endpoint", filename, None,
                "A LoadBalancer commonly creates an externally reachable endpoint, depending on your cluster and cloud settings.",
                "Confirm the service is intended to be public and restrict source ranges where supported.", "network"))
    return findings


def _terraform(content: str, filename: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        config = hcl2.loads(content)
    except Exception as exc:  # parser errors vary by library version
        line = None
        match = re.search(r"line\s+(\d+)", str(exc), re.I)
        if match:
            line = int(match.group(1))
        return [_finding("TF-000", "low", "Could not parse Terraform", filename, line,
            "This file has an HCL syntax issue, so resource checks could not run.",
            "Fix the HCL syntax and scan again. The scanner does not execute Terraform.", "validation")]

    resource_types: set[str] = set()
    for group in config.get("resource", []) or []:
        if not isinstance(group, dict):
            continue
        for resource_type, named_resources in group.items():
            resource_types.add(resource_type)
            if not isinstance(named_resources, list):
                named_resources = [named_resources]
            for item in named_resources:
                if not isinstance(item, dict):
                    continue
                for resource_name, body in item.items():
                    if not isinstance(body, dict):
                        continue
                    location = _line_for(content, rf'resource\s+"{re.escape(resource_type)}"\s+"{re.escape(resource_name)}"')
                    if resource_type == "aws_s3_bucket" and str(body.get("acl", "")).lower() in {"public-read", "public-read-write", "authenticated-read"}:
                        findings.append(_finding("TF-001", "high", "S3 bucket has a public ACL", filename, location,
                            f"Bucket {resource_name} uses ACL {body.get('acl')}, which grants access beyond its owner.",
                            "Remove the public ACL, block public access, and grant access through a scoped identity policy.", "storage"))
                    if resource_type in {"aws_security_group_rule", "aws_vpc_security_group_ingress_rule"}:
                        cidrs = body.get("cidr_blocks", []) or body.get("cidr_ipv4", []) or []
                        if isinstance(cidrs, str):
                            cidrs = [cidrs]
                        if "0.0.0.0/0" in cidrs or "::/0" in cidrs:
                            try:
                                start = int(body.get("from_port", body.get("to_port", 0)) or 0)
                            except (TypeError, ValueError):
                                start = 0
                            try:
                                end = int(body.get("to_port", start) or start)
                            except (TypeError, ValueError):
                                end = start
                            sensitive = any(start <= p <= end for p in (22, 3389, 3306, 5432, 6379, 9200)) or start == 0 and end == 0
                            severity = "high" if sensitive else "medium"
                            findings.append(_finding("TF-002", severity, "Security group allows traffic from anywhere", filename, location,
                                f"Resource {resource_name} permits ingress from a world-open CIDR range.",
                                "Limit the source CIDR to the specific trusted networks that need access.", "network"))
                    if resource_type == "aws_db_instance" and body.get("publicly_accessible") is True:
                        findings.append(_finding("TF-003", "high", "Database is publicly accessible", filename, location,
                            f"Database {resource_name} is configured for public network access.",
                            "Set publicly_accessible = false and connect through private subnets or a controlled proxy.", "network"))
                    if resource_type == "aws_db_instance" and body.get("storage_encrypted") is False:
                        findings.append(_finding("TF-004", "medium", "Database storage encryption disabled", filename, location,
                            f"Database {resource_name} explicitly disables storage encryption.",
                            "Enable storage encryption and use an approved key management policy.", "data-protection"))

    # Catch an explicit wildcard IAM action in parsed resource bodies, including nested policy documents.
    def walk(value: Any):
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() == "action":
                    actions = child if isinstance(child, list) else [child]
                    if any(str(action) == "*" for action in actions):
                        yield key
                yield from walk(child)
        elif isinstance(value, list):
            for child in value:
                yield from walk(child)
    wildcard_action = (
        _line_for(content, r"\bAction\s*=\s*(?:\[\s*)?[\"']?\*[\"']?\s*\]?")
        or _line_for(content, r"\"Action\"\s*:\s*(?:\[\s*)?[\"']?\*[\"']?\s*\]?")
    )
    if list(walk(config)) or wildcard_action:
        line = wildcard_action
        findings.append(_finding("TF-005", "high", "IAM policy grants wildcard actions", filename, line,
            "An IAM action wildcard can grant a principal far more permissions than a workload needs.",
            "Replace the wildcard with the smallest set of actions and resources required.", "identity"))
    return findings


def _json(content: str, filename: str) -> list[Finding]:
    try:
        value = json.loads(content)
    except json.JSONDecodeError as exc:
        return [_finding("JSON-000", "low", "Could not parse JSON", filename, exc.lineno,
            "This file has a JSON syntax issue, so structural checks could not run.", "Fix the JSON syntax and scan again.", "validation")]
    text = json.dumps(value)
    findings: list[Finding] = []
    for match in re.finditer(r"(?:AKIA[0-9A-Z]{16}|[\"']?(?:password|secret|token|api[_-]?key)[\"']?\s*:\s*[\"'][^\"']{8,}[\"'])", text, re.I):
        findings.append(_finding("GEN-001", "high", "Possible hard-coded credential", filename, None,
            "A value that resembles a credential appears in this configuration.", "Rotate any real credential and load it from a managed secret store at runtime.", "secrets"))
        break
    return findings


def scan_config(filename: str, content: str, file_type: str = "auto") -> list[dict[str, Any]]:
    """Scan one config by extension or explicit type and return stable finding objects."""
    if len(content.encode("utf-8")) > 1_000_000:
        raise ValueError("Configuration is larger than the 1 MB scan limit.")
    suffix = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    name = filename.lower().rsplit("/", 1)[-1]
    kind = file_type.lower()
    if kind == "auto":
        if name == "dockerfile" or suffix in {"dockerfile", "docker"}:
            kind = "dockerfile"
        elif suffix in {"tf", "tfvars", "hcl"}:
            kind = "terraform"
        elif suffix == "json":
            kind = "json"
        elif suffix in {"yaml", "yml"}:
            kind = "kubernetes"
        elif re.search(r"^\s*(?:FROM|USER|RUN|COPY|ADD)\s+", content, re.I | re.M):
            kind = "dockerfile"
        elif re.search(r"^\s*resource\s+\"", content, re.M):
            kind = "terraform"
        else:
            kind = "kubernetes"
    if kind == "dockerfile":
        findings = _dockerfile(content, filename)
    elif kind in {"kubernetes", "yaml", "yml"}:
        findings = _yaml_documents(content, filename)
    elif kind in {"terraform", "hcl", "tf"}:
        findings = _terraform(content, filename)
    elif kind == "json":
        findings = _json(content, filename)
    else:
        raise ValueError("Unsupported config type. Choose Dockerfile, Kubernetes YAML, Terraform, or JSON.")
    order = {"high": 0, "medium": 1, "low": 2}
    return [item.to_dict() for item in sorted(findings, key=lambda f: (order[f.severity], f.rule_id, f.line or 0))]
