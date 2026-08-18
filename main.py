import re
from typing import Any, Dict, List
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="TDS GA7 Policy Gate Service")

# =============================================================================
# Question 1: Release Gate (POST /release-gate)
# =============================================================================

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


# =============================================================================
# Question 2: LLM Action Firewall (POST /action-firewall)
# =============================================================================

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


# =============================================================================
# Question 3: Terraform Plan Policy Gate (POST /terraform/plan)
# =============================================================================

ASSIGNED_WORKSPACE = "prod-jf0ozw"
REQUIRED_LABELS = {
    "owner": "student-g5puu",
    "environment": "production",
    "cost_center": "cc-gar5"
}

def is_provider_pinned(pv_str: str) -> bool:
    if not isinstance(pv_str, str):
        return False
    pv = pv_str.strip()
    if not pv:
        return False
    
    if pv in ["*", "latest"] or "latest" in pv.lower() or "*" in pv:
        return False

    if pv.startswith("~>"):
        rest = pv[2:].strip()
        return bool(re.match(r"^\d+(\.\d+)+$", rest))
    
    if ">=" in pv or "<=" in pv or ">" in pv or "<" in pv:
        return False

    if pv.startswith("="):
        rest = pv[1:].strip()
        return bool(re.match(r"^\d+(\.\d+)+$", rest))

    if re.match(r"^\d+(\.\d+)+$", pv):
        return True

    return False

def evaluate_terraform_plan(payload: Dict[str, Any]) -> Dict[str, Any]:
    # Check 1: Top-level and nested value types (INVALID_PLAN)
    if not isinstance(payload, dict):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if "environment" not in payload or "state" not in payload or "providerVersion" not in payload or "destroyApproved" not in payload or "resource" not in payload:
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    env = payload["environment"]
    if not isinstance(env, str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    state = payload["state"]
    if not isinstance(state, dict):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if "backend" not in state or "locked" not in state:
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    backend = state["backend"]
    locked = state["locked"]
    if not isinstance(backend, str) or not isinstance(locked, bool):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    provider_version = payload["providerVersion"]
    if not isinstance(provider_version, str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    destroy_approved = payload["destroyApproved"]
    if not isinstance(destroy_approved, bool):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    resource = payload["resource"]
    if not isinstance(resource, dict):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if "address" not in resource or "type" not in resource or "action" not in resource or "labels" not in resource or "secret" not in resource:
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    res_address = resource["address"]
    res_type = resource["type"]
    res_action = resource["action"]
    res_labels = resource["labels"]
    res_secret = resource["secret"]

    if not isinstance(res_address, str) or not isinstance(res_type, str) or not isinstance(res_action, str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if res_action not in ["create", "update", "delete"]:
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    if not isinstance(res_labels, dict):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    for k, v in res_labels.items():
        if not isinstance(k, str) or not isinstance(v, str):
            return {"decision": "reject", "reason": "INVALID_PLAN"}

    if res_secret is not None and not isinstance(res_secret, str):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    force_destroy = resource.get("forceDestroy")
    if force_destroy is not None and not isinstance(force_destroy, bool):
        return {"decision": "reject", "reason": "INVALID_PLAN"}

    # Check 2: Environment match (ENVIRONMENT_MISMATCH)
    if env != ASSIGNED_WORKSPACE:
        return {"decision": "reject", "reason": "ENVIRONMENT_MISMATCH"}

    # Check 3: State backend & locking (STATE_UNSAFE)
    allowed_backends = {"gcs", "s3", "azurerm", "remote"}
    if backend not in allowed_backends or locked is not True:
        return {"decision": "reject", "reason": "STATE_UNSAFE"}

    # Check 4: Provider pinning (UNPINNED_PROVIDER)
    if not is_provider_pinned(provider_version):
        return {"decision": "reject", "reason": "UNPINNED_PROVIDER"}

    # Check 5: Assigned labels (MISSING_LABELS)
    for req_k, req_v in REQUIRED_LABELS.items():
        if res_labels.get(req_k) != req_v:
            return {"decision": "reject", "reason": "MISSING_LABELS"}

    # Check 6: Plaintext secret (PLAINTEXT_SECRET)
    if res_secret is not None:
        if not (res_secret.startswith("secret://") and len(res_secret) > len("secret://")):
            return {"decision": "reject", "reason": "PLAINTEXT_SECRET"}

    # Check 7: Stateful delete approval (DELETE_NOT_APPROVED)
    stateful_types = ["storage_bucket", "sql_database", "persistent_disk"]
    is_stateful = any(st in res_type for st in stateful_types)
    if res_action == "delete" and is_stateful and destroy_approved is not True:
        return {"decision": "reject", "reason": "DELETE_NOT_APPROVED"}

    # Check 8: Force destroy on storage bucket (FORCE_DESTROY)
    if "storage_bucket" in res_type and force_destroy is True:
        return {"decision": "reject", "reason": "FORCE_DESTROY"}

    # If all rules pass -> APPROVE
    return {"decision": "approve", "reason": "APPROVE"}

@app.post("/")
@app.post("/terraform/plan")
@app.post("/terraform/plan/")
@app.post("/terraform/plan/terraform/plan")
async def terraform_plan_endpoint(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    
    result = evaluate_terraform_plan(payload)
    return JSONResponse(content=result)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
