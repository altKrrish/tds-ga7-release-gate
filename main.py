import re
from typing import Any, Dict, List
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="TDS GA7 Release Gate & Action Firewall")

# -----------------------------------------------------------------------------
# Question 1: Release Gate
# -----------------------------------------------------------------------------

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
    permissions = workflow.get("permissions")
    expected_permissions = {"contents": "read", "packages": "write", "id-token": "none"}
    if not isinstance(permissions, dict) or permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # 2. Trigger & PR rule: UNSAFE_PR_TRIGGER
    wf_trigger = workflow.get("trigger")
    if wf_trigger == "pull_request_target" or event == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests & Matrix rule: TESTS_INCOMPLETE
    tests_passed = workflow.get("testsPassed")
    matrix_complete = workflow.get("matrixComplete")
    fail_fast = workflow.get("failFast")
    if tests_passed is not True or matrix_complete is not True or fail_fast is not False:
        violations.append("TESTS_INCOMPLETE")

    # 4. Action Pinning rule: MUTABLE_ACTION
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
                if not act_ref or not isinstance(act_ref, str):
                    has_mutable_action = True
                    break
            else:
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
        if ref != "refs/heads/main" or event != "push":
            violations.append("INVALID_PRODUCTION_REF")
        
        env_approval = workflow.get("environmentApproval")
        if env_approval is not True:
            violations.append("APPROVAL_REQUIRED")

    decision = "promote" if len(violations) == 0 else "block"

    return {
        "decision": decision,
        "violations": violations
    }

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


# -----------------------------------------------------------------------------
# Question 2: LLM Action Firewall
# -----------------------------------------------------------------------------

ASSIGNED_TENANT = "tenant-75q9eyt"
ASSIGNED_EMAIL_DOMAIN = "notify-869x73c.example"

def is_unsafe_html(html: str) -> bool:
    html_lower = html.lower()
    
    # 1. Check for <script> and <iframe> tags
    if re.search(r"<\s*/?\s*(script|iframe)\b", html_lower):
        return True

    # 2. Check for inline event handlers: on<event>= (e.g. onload=, onerror=, onclick=)
    if re.search(r"\bon[a-z]+\s*=", html_lower):
        return True

    # 3. Check for javascript: URLs
    if re.search(r"java\s*script\s*:", html_lower):
        return True

    decoded = html_lower.replace("&#10;", "").replace("&#13;", "").replace("&#9;", "")
    if re.search(r"java\s*script\s*:", decoded):
        return True

    return False

def evaluate_action_firewall(payload: Dict[str, Any]) -> Dict[str, Any]:
    # Check 1: Top-level schema check (INVALID_SCHEMA)
    if not isinstance(payload, dict):
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    if "provenance" not in payload or "humanApproved" not in payload or "action" not in payload:
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    provenance = payload["provenance"]
    if provenance not in ["trusted", "untrusted"]:
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    human_approved = payload["humanApproved"]
    if not isinstance(human_approved, bool):
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    if "untrustedContent" in payload and payload["untrustedContent"] is not None and not isinstance(payload["untrustedContent"], str):
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    action = payload["action"]
    if not isinstance(action, dict):
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    if "tool" not in action or "args" not in action:
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    tool = action["tool"]
    if not isinstance(tool, str):
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    args = action["args"]
    if not isinstance(args, dict):
        return {"decision": "block", "reason": "INVALID_SCHEMA"}

    # Check 2: Tool allowlist check (TOOL_NOT_ALLOWED)
    allowed_tools = {"search", "lookup_record", "send_email", "render_html"}
    if tool not in allowed_tools:
        return {"decision": "block", "reason": "TOOL_NOT_ALLOWED"}

    # Check 3: Selected tool's argument schema (INVALID_SCHEMA)
    if tool == "search":
        if set(args.keys()) != {"query"}:
            return {"decision": "block", "reason": "INVALID_SCHEMA"}
        query = args["query"]
        if not isinstance(query, str) or not (1 <= len(query) <= 200):
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

    elif tool == "lookup_record":
        if set(args.keys()) != {"tenantId", "recordId"}:
            return {"decision": "block", "reason": "INVALID_SCHEMA"}
        tenant_id = args["tenantId"]
        record_id = args["recordId"]
        if not isinstance(tenant_id, str) or not isinstance(record_id, str) or len(record_id) == 0:
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

    elif tool == "send_email":
        if set(args.keys()) != {"to", "subject", "body"}:
            return {"decision": "block", "reason": "INVALID_SCHEMA"}
        to_addr = args["to"]
        subject = args["subject"]
        body = args["body"]
        if not isinstance(to_addr, str) or not isinstance(subject, str) or not isinstance(body, str):
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

    elif tool == "render_html":
        if set(args.keys()) != {"html"}:
            return {"decision": "block", "reason": "INVALID_SCHEMA"}
        html_content = args["html"]
        if not isinstance(html_content, str):
            return {"decision": "block", "reason": "INVALID_SCHEMA"}

    # Check 4: Tenant scope (TENANT_SCOPE)
    if tool == "lookup_record":
        if args["tenantId"] != ASSIGNED_TENANT:
            return {"decision": "block", "reason": "TENANT_SCOPE"}

    # Check 5: Email domain check (EGRESS_DENIED)
    if tool == "send_email":
        to_str = args["to"].strip()
        if "@" in to_str:
            domain = to_str.split("@")[-1].strip().lower()
        else:
            domain = ""
        if domain != ASSIGNED_EMAIL_DOMAIN.lower():
            return {"decision": "block", "reason": "EGRESS_DENIED"}

    # Check 6: Human approval check (APPROVAL_REQUIRED)
    if tool == "send_email":
        if not human_approved:
            return {"decision": "block", "reason": "APPROVAL_REQUIRED"}

    # Check 7: HTML safety check (UNSAFE_OUTPUT)
    if tool == "render_html":
        if is_unsafe_html(args["html"]):
            return {"decision": "block", "reason": "UNSAFE_OUTPUT"}

    # If no rule fails -> ALLOW
    return {"decision": "allow", "reason": "ALLOW"}

@app.post("/")
@app.post("/action-firewall")
@app.post("/action-firewall/")
@app.post("/action-firewall/action-firewall")
async def action_firewall_endpoint(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    
    result = evaluate_action_firewall(payload)
    return JSONResponse(content=result)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
