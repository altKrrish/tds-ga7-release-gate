import re
from typing import Any, Dict, List
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="CI/CD Container Release Gate")

SHA_REGEX = re.compile(r"^[0-9a-f]{40}$")

def evaluate_release_gate(payload: Dict[str, Any]) -> Dict[str, Any]:
    violations: List[str] = []

    target = payload.get("target")
    event = payload.get("event")
    ref = payload.get("ref")
    
    workflow = payload.get("workflow")
    if not isinstance(workflow, dict):
        workflow = {}
        
    image = payload.get("image")
    if not isinstance(image, dict):
        image = {}

    # 1. Permissions rule: EXCESS_PERMISSION
    # Permissions must be exactly least privilege for a release: contents: read, packages: write, and id-token: none. No additional scopes may be present.
    permissions = workflow.get("permissions")
    expected_permissions = {"contents": "read", "packages": "write", "id-token": "none"}
    if not isinstance(permissions, dict) or permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # 2. Trigger & PR rule: UNSAFE_PR_TRIGGER
    # A pull request must use pull_request, never pull_request_target.
    wf_trigger = workflow.get("trigger")
    if wf_trigger == "pull_request_target" or event == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests & Matrix rule: TESTS_INCOMPLETE
    # Tests must pass, the whole matrix must finish, and failFast must be false.
    tests_passed = workflow.get("testsPassed")
    matrix_complete = workflow.get("matrixComplete")
    fail_fast = workflow.get("failFast")
    if tests_passed is not True or matrix_complete is not True or fail_fast is not False:
        violations.append("TESTS_INCOMPLETE")

    # 4. Action Pinning rule: MUTABLE_ACTION
    # Actions owned by actions may use a version tag. Every third-party action must be pinned to a full 40-character lowercase hexadecimal commit SHA.
    actions = workflow.get("actions")
    has_mutable_action = False
    if isinstance(actions, list):
        for act in actions:
            if not isinstance(act, dict):
                has_mutable_action = True
                break
            owner = act.get("owner")
            act_ref = act.get("ref")
            if owner == "actions":
                # Actions owned by 'actions' may use a version tag (or SHA)
                if not act_ref or not isinstance(act_ref, str):
                    has_mutable_action = True
                    break
            else:
                # Third-party action must be pinned to a full 40-character lowercase hex commit SHA
                if not isinstance(act_ref, str) or not SHA_REGEX.match(act_ref):
                    has_mutable_action = True
                    break
    else:
        has_mutable_action = True

    if has_mutable_action:
        violations.append("MUTABLE_ACTION")

    # 5. Multi-stage image rule: SINGLE_STAGE_IMAGE
    multi_stage = image.get("multiStage")
    if multi_stage is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. Root runtime rule: ROOT_RUNTIME
    runs_as_root = image.get("runsAsRoot")
    if runs_as_root is not False:
        violations.append("ROOT_RUNTIME")

    # 7. Secret mode rule: SECRET_IN_LAYER
    secret_mode = image.get("secretMode")
    if secret_mode not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")

    # 8. Critical vulnerabilities rule: CRITICAL_CVE
    crit_cves = image.get("criticalVulnerabilities")
    if crit_cves != 0:
        violations.append("CRITICAL_CVE")

    # 9. Digest pinned rule: UNPINNED_IMAGE
    digest_pinned = image.get("digestPinned")
    if digest_pinned is not True:
        violations.append("UNPINNED_IMAGE")

    # 10 & 11. Production target rules
    if target == "production":
        # Production additionally requires a push on refs/heads/main
        if ref != "refs/heads/main" or event != "push":
            violations.append("INVALID_PRODUCTION_REF")
        
        # and an environmentApproval: true field on workflow.
        env_approval = workflow.get("environmentApproval")
        if env_approval is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if len(violations) == 0 else "block"

    return {
        "decision": decision,
        "violations": violations
    }

@app.post("/")
@app.post("/release-gate")
@app.post("/release-gate/")
@app.post("/release-gate/release-gate")
async def release_gate_endpoint(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    
    result = evaluate_release_gate(payload)
    return JSONResponse(content=result)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
