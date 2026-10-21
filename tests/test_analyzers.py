import unittest

from scanner.analyzers import scan_config


class AnalyzerTests(unittest.TestCase):
    def ids(self, findings):
        return {finding["rule_id"] for finding in findings}

    def test_dockerfile_flags_root_latest_and_secret(self):
        content = "FROM nginx:latest\nENV API_KEY=not-a-real-secret-value\nUSER root\n"
        findings = scan_config("Dockerfile", content)
        self.assertTrue({"DOCKER-001", "DOCKER-002", "DOCKER-004"}.issubset(self.ids(findings)))
        self.assertEqual("high", next(f["severity"] for f in findings if f["rule_id"] == "DOCKER-001"))

    def test_kubernetes_checks_nested_deployment_pod(self):
        content = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: demo
spec:
  template:
    spec:
      hostNetwork: true
      containers:
      - name: web
        image: nginx:latest
        securityContext:
          privileged: true
"""
        findings = scan_config("deployment.yaml", content)
        self.assertTrue({"K8S-002", "K8S-004", "K8S-005", "K8S-007"}.issubset(self.ids(findings)))

    def test_terraform_checks_public_s3_and_world_open_ssh(self):
        content = '''resource "aws_s3_bucket" "data" {
  bucket = "demo"
  acl    = "public-read"
}
resource "aws_security_group_rule" "ssh" {
  type = "ingress"
  from_port = 22
  to_port = 22
  protocol = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
'''
        findings = scan_config("main.tf", content)
        self.assertTrue({"TF-001", "TF-002"}.issubset(self.ids(findings)))

    def test_terraform_flags_wildcard_iam_action(self):
        content = '''resource "aws_iam_policy" "wide" {
  policy = jsonencode({ Statement = [{ Action = ["*"] Effect = "Allow" Resource = "*" }] })
}
'''
        self.assertIn("TF-005", self.ids(scan_config("policy.tf", content)))

    def test_invalid_yaml_returns_parse_finding(self):
        findings = scan_config("broken.yaml", "kind: Pod\n  invalid_indent: yes")
        self.assertIn("YAML-000", self.ids(findings))

    def test_rejects_oversized_input(self):
        with self.assertRaises(ValueError):
            scan_config("Dockerfile", "x" * 1_000_001)

    def test_json_flags_credential_like_value(self):
        findings = scan_config("settings.json", '{"API_KEY":"sample-secret-value"}')
        self.assertIn("GEN-001", self.ids(findings))


if __name__ == "__main__":
    unittest.main()
