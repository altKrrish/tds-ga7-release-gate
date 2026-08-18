import html
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="TDS GA7 Policy Gate & Corroboration Engine")

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

    permissions = workflow.get("permissions")
    expected_permissions = {"contents": "read", "packages": "write", "id-token": "none"}
    if not isinstance(permissions, dict) or permissions != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    wf_trigger = workflow.get("trigger")
    if wf_trigger == "pull_request_target" or event == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    tests_passed = workflow.get("testsPassed")
    matrix_complete = workflow.get("matrixComplete")
    fail_fast = workflow.get("failFast")
    if tests_passed is not True or matrix_complete is not True or fail_fast is not False:
        violations.append("TESTS_INCOMPLETE")

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

    multi_stage = image.get("multiStage")
    if multi_stage is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    runs_as_root = image.get("runsAsRoot")
    if runs_as_root is not False:
        violations.append("ROOT_RUNTIME")

    secret_mode = image.get("secretMode")
    if secret_mode not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")

    crit_cves = image.get("criticalVulnerabilities")
    if crit_cves != 0:
        violations.append("CRITICAL_CVE")

    digest_pinned = image.get("digestPinned")
    if digest_pinned is not True:
        violations.append("UNPINNED_IMAGE")

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

def is_unsafe_html(html_str: str) -> bool:
    html_lower = html_str.lower()
    
    if re.search(r"<\s*/?\s*(script|iframe)\b", html_lower):
        return True

    if re.search(r"\bon[a-z]+\s*=", html_lower):
        return True

    if re.search(r"java\s*script\s*:", html_lower):
        return True

    decoded = html_lower.replace("&#10;", "").replace("&#13;", "").replace("&#9;", "")
    if re.search(r"java\s*script\s*:", decoded):
        return True

    return False

def evaluate_action_firewall(payload: Dict[str, Any]) -> Dict[str, Any]:
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

    allowed_tools = {"search", "lookup_record", "send_email", "render_html"}
    if tool not in allowed_tools:
        return {"decision": "block", "reason": "TOOL_NOT_ALLOWED"}

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

    if tool == "lookup_record":
        if args["tenantId"] != ASSIGNED_TENANT:
            return {"decision": "block", "reason": "TENANT_SCOPE"}

    if tool == "send_email":
        to_str = args["to"].strip()
        if "@" in to_str:
            domain = to_str.split("@")[-1].strip().lower()
        else:
            domain = ""
        if domain != ASSIGNED_EMAIL_DOMAIN.lower():
            return {"decision": "block", "reason": "EGRESS_DENIED"}

    if tool == "send_email":
        if not human_approved:
            return {"decision": "block", "reason": "APPROVAL_REQUIRED"}

    if tool == "render_html":
        if is_unsafe_html(args["html"]):
            return {"decision": "block", "reason": "UNSAFE_OUTPUT"}

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

    if env != ASSIGNED_WORKSPACE:
        return {"decision": "reject", "reason": "ENVIRONMENT_MISMATCH"}

    allowed_backends = {"gcs", "s3", "azurerm", "remote"}
    if backend not in allowed_backends or locked is not True:
        return {"decision": "reject", "reason": "STATE_UNSAFE"}

    if not is_provider_pinned(provider_version):
        return {"decision": "reject", "reason": "UNPINNED_PROVIDER"}

    for req_k, req_v in REQUIRED_LABELS.items():
        if res_labels.get(req_k) != req_v:
            return {"decision": "reject", "reason": "MISSING_LABELS"}

    if res_secret is not None:
        if not (res_secret.startswith("secret://") and len(res_secret) > len("secret://")):
            return {"decision": "reject", "reason": "PLAINTEXT_SECRET"}

    stateful_types = ["storage_bucket", "sql_database", "persistent_disk"]
    is_stateful = any(st in res_type for st in stateful_types)
    if res_action == "delete" and is_stateful and destroy_approved is not True:
        return {"decision": "reject", "reason": "DELETE_NOT_APPROVED"}

    if "storage_bucket" in res_type and force_destroy is True:
        return {"decision": "reject", "reason": "FORCE_DESTROY"}

    return {"decision": "approve", "reason": "APPROVE"}

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


# =============================================================================
# Question 4: LLM Output Handling Gate (POST /sanitize-output)
# =============================================================================

ALLOWED_HOSTS_Q4 = {"cdn-i27fuzj.example", "app-5dt5fud.example"}

def extract_urls_q4(channel: str, text: str) -> List[str]:
    urls = []
    if channel == "html":
        matches = re.findall(r"""\b(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))""", text, re.IGNORECASE)
        for m in matches:
            val = m[0] or m[1] or m[2]
            if val:
                urls.append(val.strip())
    elif channel == "markdown":
        matches = re.findall(r"\]\(([^)]+)\)", text)
        for m in matches:
            target = m.strip()
            parts = target.split()
            if parts:
                urls.append(parts[0].strip())
    elif channel == "url":
        urls.append(text.strip())
    return urls

def check_dangerous_scheme_q4(channel: str, text: str, urls: List[str]) -> bool:
    if re.search(r"\b(javascript|data|vbscript)\s*:", text, re.IGNORECASE):
        return True

    for u in urls:
        raw_u = u.strip()
        if raw_u.startswith("//"):
            raw_u = "https:" + raw_u
        
        parsed = urllib.parse.urlparse(raw_u)
        scheme = parsed.scheme.lower()
        if scheme:
            if scheme not in ["http", "https"]:
                return True

    return False

def check_external_exfil_q4(urls: List[str]) -> bool:
    for u in urls:
        raw_u = u.strip()
        if not raw_u:
            continue
        
        is_protocol_relative = raw_u.startswith("//")
        if is_protocol_relative:
            raw_u = "https:" + raw_u
            
        parsed = urllib.parse.urlparse(raw_u)
        scheme = parsed.scheme.lower()
        
        is_absolute = is_protocol_relative or bool(scheme) or bool(parsed.netloc) or raw_u.startswith("http://") or raw_u.startswith("https://")
        
        if is_absolute:
            hostname = parsed.hostname
            if not hostname:
                return True
            
            if hostname.lower() not in ALLOWED_HOSTS_Q4:
                return True
    return False

def evaluate_channel_rules_q4(channel: str, text: str) -> str:
    if channel == "html":
        if re.search(r"<\s*(script|iframe|object|embed)\b", text, re.IGNORECASE):
            return "SCRIPT_TAG"

        if re.search(r"\bon[a-z0-9_-]+\s*=", text, re.IGNORECASE):
            return "EVENT_HANDLER"

        urls = extract_urls_q4("html", text)

        if check_dangerous_scheme_q4("html", text, urls):
            return "DANGEROUS_SCHEME"

        if check_external_exfil_q4(urls):
            return "EXTERNAL_EXFIL"

    elif channel == "markdown":
        urls = extract_urls_q4("markdown", text)

        if check_dangerous_scheme_q4("markdown", text, urls):
            return "DANGEROUS_SCHEME"

        if check_external_exfil_q4(urls):
            return "EXTERNAL_EXFIL"

    elif channel == "url":
        urls = extract_urls_q4("url", text)

        if check_dangerous_scheme_q4("url", text, urls):
            return "DANGEROUS_SCHEME"

        if check_external_exfil_q4(urls):
            return "EXTERNAL_EXFIL"

    elif channel == "sql":
        if "'" in text or '"' in text or ";" in text or "--" in text or "/*" in text:
            return "SQL_METACHAR"
        if re.search(r"\bunion\b", text, re.IGNORECASE):
            return "SQL_METACHAR"
        if re.search(r"\bor\s+1\s*=\s*1\b", text, re.IGNORECASE):
            return "SQL_METACHAR"

    elif channel == "shell":
        shell_metachars = [";", "&", "|", "`", "<", ">", "$(", "${"]
        if any(c in text for c in shell_metachars):
            return "SHELL_METACHAR"

    return "SAFE"

def decode_output_q4(text: str) -> str:
    s = text
    try:
        s = urllib.parse.unquote(s)
    except Exception:
        pass

    try:
        s = html.unescape(s)
    except Exception:
        pass

    def unescape_unicode(m):
        try:
            return chr(int(m.group(1), 16))
        except Exception:
            return m.group(0)

    s = re.sub(r"\\u([0-9a-fA-F]{4})", unescape_unicode, s)
    return s

def evaluate_sanitize_output(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {"safe": False, "reason": "INVALID_SCHEMA"}

    if "channel" not in payload or "output" not in payload:
        return {"safe": False, "reason": "INVALID_SCHEMA"}

    channel = payload["channel"]
    output = payload["output"]

    if not isinstance(channel, str) or not isinstance(output, str):
        return {"safe": False, "reason": "INVALID_SCHEMA"}

    allowed_channels = {"html", "markdown", "url", "sql", "shell"}
    if channel not in allowed_channels:
        return {"safe": False, "reason": "INVALID_SCHEMA"}

    if len(output) > 20000:
        return {"safe": False, "reason": "INVALID_SCHEMA"}

    decoded = decode_output_q4(output)
    if decoded != output:
        decoded_reason = evaluate_channel_rules_q4(channel, decoded)
        if decoded_reason != "SAFE":
            return {"safe": False, "reason": "ENCODED_PAYLOAD"}

    final_reason = evaluate_channel_rules_q4(channel, output)
    is_safe = (final_reason == "SAFE")

    return {
        "safe": is_safe,
        "reason": final_reason
    }

@app.post("/sanitize-output")
@app.post("/sanitize-output/")
@app.post("/sanitize-output/sanitize-output")
async def sanitize_output_endpoint(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    
    result = evaluate_sanitize_output(payload)
    return JSONResponse(content=result)


# =============================================================================
# Question 5: OSINT Corroboration Engine (POST /corroborate)
# =============================================================================

VALID_SOURCE_TYPES = {"dns", "ct_log", "registry", "archive", "scan"}

def parse_iso_datetime(dt_str: str) -> Optional[datetime]:
    if not isinstance(dt_str, str):
        return None
    try:
        s = dt_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None

def is_valid_source(src: Any) -> bool:
    if not isinstance(src, dict):
        return False
    
    src_id = src.get("id")
    origin = src.get("origin")
    val = src.get("value")
    obs_at = src.get("observedAt")
    stype = src.get("type")
    
    if not isinstance(src_id, str) or not isinstance(origin, str) or not isinstance(val, str) or not isinstance(obs_at, str):
        return False
    
    if stype not in VALID_SOURCE_TYPES:
        return False

    if parse_iso_datetime(obs_at) is None:
        return False

    auth = src.get("authoritative", False)
    if not isinstance(auth, bool):
        return False

    return True

def evaluate_corroborate(payload: Dict[str, Any]) -> Dict[str, Any]:
    # Rule 1: invalid
    # the body is not an object, claim.value is not a string, asOf is missing or unparseable, stalenessDays is not a number, or sources is not an array.
    if not isinstance(payload, dict):
        return {"verdict": "invalid", "confidence": "low", "corroboratingSources": []}

    claim = payload.get("claim")
    if not isinstance(claim, dict):
        return {"verdict": "invalid", "confidence": "low", "corroboratingSources": []}

    claim_val = claim.get("value")
    if not isinstance(claim_val, str):
        return {"verdict": "invalid", "confidence": "low", "corroboratingSources": []}

    as_of_str = payload.get("asOf")
    as_of_dt = parse_iso_datetime(as_of_str)
    if as_of_dt is None:
        return {"verdict": "invalid", "confidence": "low", "corroboratingSources": []}

    staleness_days = payload.get("stalenessDays")
    if not isinstance(staleness_days, (int, float)) or isinstance(staleness_days, bool) or staleness_days < 0:
        return {"verdict": "invalid", "confidence": "low", "corroboratingSources": []}

    sources = payload.get("sources")
    if not isinstance(sources, list):
        return {"verdict": "invalid", "confidence": "low", "corroboratingSources": []}

    # Filter valid sources
    valid_sources = [s for s in sources if is_valid_source(s)]

    # Freshness helper: asOf - observedAt <= stalenessDays (and observedAt <= asOf)
    max_stale_sec = staleness_days * 86400.0

    def is_fresh(src: Dict[str, Any]) -> bool:
        obs_dt = parse_iso_datetime(src["observedAt"])
        if obs_dt is None:
            return False
        delta_sec = (as_of_dt - obs_dt).total_seconds()
        return 0 <= delta_sec <= max_stale_sec

    # Rule 2: contradicted
    # at least one fresh source with authoritative: true reports a value different from the claim.
    # Confidence low. corroboratingSources = the ids of those contradicting sources, sorted ascending.
    contradicting_sources = [
        s for s in valid_sources
        if is_fresh(s) and s.get("authoritative") is True and s["value"] != claim_val
    ]

    if len(contradicting_sources) > 0:
        contradicting_ids = sorted(list(set(s["id"] for s in contradicting_sources)))
        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": contradicting_ids
        }

    # Rule 3: supported
    # after keeping only fresh sources whose value equals the claim, and reducing them to one representative per origin
    # (the representative is the source with the lexicographically smallest id for that origin), two or more representatives remain.
    matching_fresh_sources = [
        s for s in valid_sources
        if is_fresh(s) and s["value"] == claim_val
    ]

    # Group by origin
    origin_groups: Dict[str, List[Dict[str, Any]]] = {}
    for s in matching_fresh_sources:
        orig = s["origin"]
        if orig not in origin_groups:
            origin_groups[orig] = []
        origin_groups[orig].append(s)

    # Find representative for each origin (lexicographically smallest id)
    representatives: List[Dict[str, Any]] = []
    for orig, group in origin_groups.items():
        rep = min(group, key=lambda x: x["id"])
        representatives.append(rep)

    if len(representatives) >= 2:
        distinct_types = set(r["type"] for r in representatives)
        confidence = "high" if len(distinct_types) >= 2 else "medium"
        rep_ids = sorted([r["id"] for r in representatives])
        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": rep_ids
        }

    # Rule 4: unverified
    return {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": []
    }

@app.post("/corroborate")
@app.post("/corroborate/")
@app.post("/corroborate/corroborate")
async def corroborate_endpoint(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    
    result = evaluate_corroborate(payload)
    return JSONResponse(content=result)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
