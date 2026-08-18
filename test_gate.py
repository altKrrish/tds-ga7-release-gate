import unittest
from main import evaluate_release_gate

def get_base_preview_payload():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature/branch",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {"owner": "actions", "name": "checkout", "ref": "v4"},
                {"owner": "docker", "name": "build-push-action", "ref": "a" * 40}
            ]
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "buildkit",
            "criticalVulnerabilities": 0,
            "digestPinned": True
        }
    }

def get_base_production_payload():
    payload = get_base_preview_payload()
    payload["target"] = "production"
    payload["event"] = "push"
    payload["ref"] = "refs/heads/main"
    payload["workflow"]["trigger"] = "push"
    payload["workflow"]["environmentApproval"] = True
    return payload

class TestReleaseGate(unittest.TestCase):
    def test_valid_preview_promote(self):
        payload = get_base_preview_payload()
        res = evaluate_release_gate(payload)
        self.assertEqual(res, {"decision": "promote", "violations": []})

    def test_valid_production_promote(self):
        payload = get_base_production_payload()
        res = evaluate_release_gate(payload)
        self.assertEqual(res, {"decision": "promote", "violations": []})

    def test_excess_permission_extra_scope(self):
        payload = get_base_preview_payload()
        payload["workflow"]["permissions"]["deployments"] = "write"
        res = evaluate_release_gate(payload)
        self.assertIn("EXCESS_PERMISSION", res["violations"])
        self.assertEqual(res["decision"], "block")

    def test_excess_permission_missing_scope(self):
        payload = get_base_preview_payload()
        del payload["workflow"]["permissions"]["id-token"]
        res = evaluate_release_gate(payload)
        self.assertIn("EXCESS_PERMISSION", res["violations"])

    def test_excess_permission_wrong_value(self):
        payload = get_base_preview_payload()
        payload["workflow"]["permissions"]["contents"] = "write"
        res = evaluate_release_gate(payload)
        self.assertIn("EXCESS_PERMISSION", res["violations"])

    def test_unsafe_pr_trigger(self):
        payload = get_base_preview_payload()
        payload["workflow"]["trigger"] = "pull_request_target"
        res = evaluate_release_gate(payload)
        self.assertIn("UNSAFE_PR_TRIGGER", res["violations"])

    def test_tests_incomplete_tests_passed_false(self):
        payload = get_base_preview_payload()
        payload["workflow"]["testsPassed"] = False
        res = evaluate_release_gate(payload)
        self.assertIn("TESTS_INCOMPLETE", res["violations"])

    def test_tests_incomplete_matrix_incomplete(self):
        payload = get_base_preview_payload()
        payload["workflow"]["matrixComplete"] = False
        res = evaluate_release_gate(payload)
        self.assertIn("TESTS_INCOMPLETE", res["violations"])

    def test_tests_incomplete_fail_fast_true(self):
        payload = get_base_preview_payload()
        payload["workflow"]["failFast"] = True
        res = evaluate_release_gate(payload)
        self.assertIn("TESTS_INCOMPLETE", res["violations"])

    def test_mutable_action_third_party_version_tag(self):
        payload = get_base_preview_payload()
        payload["workflow"]["actions"].append({"owner": "thirdparty", "name": "setup", "ref": "v1.0"})
        res = evaluate_release_gate(payload)
        self.assertIn("MUTABLE_ACTION", res["violations"])

    def test_mutable_action_third_party_uppercase_sha(self):
        payload = get_base_preview_payload()
        payload["workflow"]["actions"].append({"owner": "thirdparty", "name": "setup", "ref": "A" * 40})
        res = evaluate_release_gate(payload)
        self.assertIn("MUTABLE_ACTION", res["violations"])

    def test_official_action_version_tag_allowed(self):
        payload = get_base_preview_payload()
        payload["workflow"]["actions"] = [{"owner": "actions", "name": "checkout", "ref": "v4.1.0"}]
        res = evaluate_release_gate(payload)
        self.assertNotIn("MUTABLE_ACTION", res["violations"])

    def test_single_stage_image(self):
        payload = get_base_preview_payload()
        payload["image"]["multiStage"] = False
        res = evaluate_release_gate(payload)
        self.assertIn("SINGLE_STAGE_IMAGE", res["violations"])

    def test_root_runtime(self):
        payload = get_base_preview_payload()
        payload["image"]["runsAsRoot"] = True
        res = evaluate_release_gate(payload)
        self.assertIn("ROOT_RUNTIME", res["violations"])

    def test_secret_in_layer_arg(self):
        payload = get_base_preview_payload()
        payload["image"]["secretMode"] = "arg"
        res = evaluate_release_gate(payload)
        self.assertIn("SECRET_IN_LAYER", res["violations"])

    def test_secret_in_layer_copy(self):
        payload = get_base_preview_payload()
        payload["image"]["secretMode"] = "copy"
        res = evaluate_release_gate(payload)
        self.assertIn("SECRET_IN_LAYER", res["violations"])

    def test_secret_mode_none_allowed(self):
        payload = get_base_preview_payload()
        payload["image"]["secretMode"] = "none"
        res = evaluate_release_gate(payload)
        self.assertNotIn("SECRET_IN_LAYER", res["violations"])

    def test_critical_cve(self):
        payload = get_base_preview_payload()
        payload["image"]["criticalVulnerabilities"] = 1
        res = evaluate_release_gate(payload)
        self.assertIn("CRITICAL_CVE", res["violations"])

    def test_unpinned_image(self):
        payload = get_base_preview_payload()
        payload["image"]["digestPinned"] = False
        res = evaluate_release_gate(payload)
        self.assertIn("UNPINNED_IMAGE", res["violations"])

    def test_invalid_production_ref_branch(self):
        payload = get_base_production_payload()
        payload["ref"] = "refs/heads/feature"
        res = evaluate_release_gate(payload)
        self.assertIn("INVALID_PRODUCTION_REF", res["violations"])

    def test_invalid_production_ref_event(self):
        payload = get_base_production_payload()
        payload["event"] = "pull_request"
        res = evaluate_release_gate(payload)
        self.assertIn("INVALID_PRODUCTION_REF", res["violations"])

    def test_approval_required(self):
        payload = get_base_production_payload()
        payload["workflow"]["environmentApproval"] = False
        res = evaluate_release_gate(payload)
        self.assertIn("APPROVAL_REQUIRED", res["violations"])

    def test_all_violations_combined(self):
        payload = {
            "target": "production",
            "event": "pull_request",
            "ref": "refs/heads/dev",
            "workflow": {
                "trigger": "pull_request_target",
                "permissions": {"contents": "write", "packages": "write", "id-token": "none", "extra": "scope"},
                "testsPassed": False,
                "matrixComplete": False,
                "failFast": True,
                "environmentApproval": False,
                "actions": [{"owner": "thirdparty", "name": "bad", "ref": "v1"}]
            },
            "image": {
                "multiStage": False,
                "runsAsRoot": True,
                "secretMode": "arg",
                "criticalVulnerabilities": 5,
                "digestPinned": False
            }
        }
        res = evaluate_release_gate(payload)
        expected_violations = {
            "EXCESS_PERMISSION", "UNSAFE_PR_TRIGGER", "TESTS_INCOMPLETE",
            "MUTABLE_ACTION", "SINGLE_STAGE_IMAGE", "ROOT_RUNTIME",
            "SECRET_IN_LAYER", "CRITICAL_CVE", "UNPINNED_IMAGE",
            "INVALID_PRODUCTION_REF", "APPROVAL_REQUIRED"
        }
        self.assertEqual(set(res["violations"]), expected_violations)
        self.assertEqual(res["decision"], "block")

if __name__ == "__main__":
    unittest.main()
