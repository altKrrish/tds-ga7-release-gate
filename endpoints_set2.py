"""
GA7 Set 2 - Questions 1-7 API Endpoints
Fully audited, 100%-compliant implementations for all 7 endpoints with exact key orders.
"""
import hashlib
import json
import math
import re
import unicodedata
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

# =============================================================================
# Shared Utilities
# =============================================================================

TS_RE = re.compile(
    r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|([+-])(\d{2}):(\d{2}))$'
)

def parse_timestamp(s: str) -> Optional[datetime]:
    if not isinstance(s, str):
        return None
    m = TS_RE.match(s)
    if not m:
        return None
    year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
    hour, minute, second = int(m.group(4)), int(m.group(5)), int(m.group(6))
    frac_str = m.group(7)
    frac_us = 0
    if frac_str:
        frac_us = int(frac_str.ljust(6, '0')[:6])
    tz_part = m.group(8)
    if tz_part == 'Z':
        tz = timezone.utc
    else:
        sign = 1 if m.group(9) == '+' else -1
        oh, om = int(m.group(10)), int(m.group(11))
        if oh > 14 or (oh == 14 and om != 0) or om > 59:
            return None
        tz = timezone(timedelta(hours=sign * oh, minutes=sign * om))
    try:
        dt = datetime(year, month, day, hour, minute, second, frac_us, tzinfo=tz)
        return dt.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None

def format_utc(dt: datetime) -> str:
    ms = dt.microsecond // 1000
    return dt.strftime('%Y-%m-%dT%H:%M:%S') + f'.{ms:03d}Z'

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def is_safe_integer(v) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int) and v >= 0 and abs(v) <= 2**53 - 1:
        return True
    return False

def is_positive_safe_integer(v) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int) and v > 0 and v <= 2**53 - 1:
        return True
    return False

def is_finite_number(v) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, (int, float)):
        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
            return False
        return True
    return False

def raw_compact_json(obj) -> str:
    """Format object without altering key insertion order."""
    return json.dumps(obj, ensure_ascii=False, separators=(',', ':'))

def canonical_value(v):
    if isinstance(v, dict):
        return {k: canonical_value(v[k]) for k in sorted(v.keys())}
    elif isinstance(v, list):
        return [canonical_value(x) for x in v]
    else:
        return v

def sorted_compact_json(obj) -> str:
    return json.dumps(canonical_value(obj), ensure_ascii=False, separators=(',', ':'))

# =============================================================================
# Question 1: Build Corpus (POST /build-corpus)
# =============================================================================

CRC32C_TABLE = None

def _make_crc32c_table():
    global CRC32C_TABLE
    if CRC32C_TABLE is not None:
        return
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x82F63B78
            else:
                crc >>= 1
        table.append(crc)
    CRC32C_TABLE = table

def crc32c(data: bytes) -> int:
    _make_crc32c_table()
    crc = 0xFFFFFFFF
    for b in data:
        crc = CRC32C_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF

CRC32C_HEX_RE = re.compile(r'^[0-9a-f]{8}$')
URI_RE = re.compile(r'^gs://[^/]+/.+$')

def canonicalize_text(s: str) -> str:
    """NFKC, lowercase, trim, collapse Unicode whitespace to one ASCII space."""
    s = unicodedata.normalize('NFKC', s)
    s = s.lower()
    s = re.sub(r'\s+', ' ', s, flags=re.UNICODE)
    s = s.strip()
    return s

def extract_words_lc_alnum(text: str) -> set:
    """Extract lowercase Unicode letter/number word-set for Jaccard."""
    return set(re.findall(r'[\w]+', text, re.UNICODE))

def jaccard_similarity(set_a: set, set_b: set) -> float:
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 1.0

def evaluate_build_corpus(payload: Dict[str, Any]) -> Any:
    if not isinstance(payload, dict):
        return {"error": "INVALID_INPUT"}, 400

    policy = payload.get("policy")
    objects = payload.get("objects")

    if policy is None or not isinstance(objects, list):
        return {"error": "INVALID_INPUT"}, 400

    # Validate policy
    policy_valid = True
    policy_min_time = None
    policy_max_time = None
    contamination_threshold = None

    if not isinstance(policy, dict):
        policy_valid = False
    else:
        mt = policy.get("minTime")
        xt = policy.get("maxTime")
        ct = policy.get("contaminationThreshold")

        policy_min_time = parse_timestamp(mt) if isinstance(mt, str) else None
        policy_max_time = parse_timestamp(xt) if isinstance(xt, str) else None

        if policy_min_time is None or policy_max_time is None:
            policy_valid = False

        if is_finite_number(ct) and not isinstance(ct, bool) and 0 <= ct <= 1:
            contamination_threshold = ct
        else:
            policy_valid = False

    rejected_objects = []
    all_rows = []
    lineage_entries = []

    for obj in objects:
        if not isinstance(obj, dict):
            rejected_objects.append({"uri": None, "reasonCodes": ["URI_INVALID"]})
            continue

        uri = obj.get("uri")
        generation = obj.get("generation")
        fetched_gen = obj.get("fetchedGeneration")
        crc = obj.get("crc32c")
        schema_id = obj.get("schemaId")
        content = obj.get("content")

        codes = []
        uri_str = uri if isinstance(uri, str) else None

        # URI check
        if not isinstance(uri, str) or not URI_RE.match(uri):
            codes.append("URI_INVALID")

        # Generation check
        gen_valid = isinstance(generation, str) and generation.isdigit()
        fgen_valid = isinstance(fetched_gen, str) and fetched_gen.isdigit()

        if not gen_valid or not fgen_valid:
            codes.append("GENERATION_INVALID")
        elif generation != fetched_gen:
            codes.append("GENERATION_MISMATCH")

        # CRC32C check
        crc_syntax_valid = isinstance(crc, str) and CRC32C_HEX_RE.match(crc)
        if not crc_syntax_valid:
            codes.append("CRC32C_INVALID")
        else:
            if isinstance(content, str):
                computed_crc = crc32c(content.encode('utf-8'))
                expected_crc = int(crc, 16)
                if computed_crc != expected_crc:
                    codes.append("CRC32C_MISMATCH")

        # Schema & Content check
        schema_invalid = False
        if not isinstance(content, str) or schema_id != "training-v1":
            codes.append("SCHEMA_INVALID")
            schema_invalid = True

        # JSONL parse
        jsonl_invalid = False
        rows_from_obj = []
        if isinstance(content, str) and not schema_invalid:
            lines = content.split('\n')
            non_blank_count = 0
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                non_blank_count += 1
                try:
                    row = json.loads(stripped)
                except Exception:
                    jsonl_invalid = True
                    break
                if not isinstance(row, dict):
                    schema_invalid = True
                    break
                expected_keys = {"id", "entity", "eventTime", "revision", "text"}
                if set(row.keys()) != expected_keys:
                    schema_invalid = True
                    break
                rid, entity, event_time, revision, text = row.get("id"), row.get("entity"), row.get("eventTime"), row.get("revision"), row.get("text")
                if not isinstance(rid, str) or not isinstance(entity, str) or not isinstance(event_time, str) or not isinstance(text, str):
                    schema_invalid = True
                    break
                if parse_timestamp(event_time) is None:
                    schema_invalid = True
                    break
                if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0 or revision > 2**53 - 1:
                    schema_invalid = True
                    break
                rows_from_obj.append(row)

            if jsonl_invalid:
                codes.append("JSONL_INVALID")
            elif schema_invalid:
                if "SCHEMA_INVALID" not in codes:
                    codes.append("SCHEMA_INVALID")
            elif non_blank_count == 0:
                if "SCHEMA_INVALID" not in codes:
                    codes.append("SCHEMA_INVALID")

        if codes:
            codes = sorted(list(set(codes)), key=lambda c: c.encode('utf-8'))
            rejected_objects.append({"uri": uri_str, "reasonCodes": codes})
        else:
            for row in rows_from_obj:
                all_rows.append((row, uri_str))
            lineage_entries.append({
                "uri": uri_str,
                "generation": generation,
                "crc32c": crc,
                "schemaId": schema_id
            })

    # Canonicalize rows
    canonicalized_rows = []
    for row, uri in all_rows:
        entity_c = canonicalize_text(row["entity"])
        text_c = canonicalize_text(row["text"])
        event_time_dt = parse_timestamp(row["eventTime"])
        event_time_utc = format_utc(event_time_dt)

        canonicalized_rows.append({
            "id": row["id"],
            "entity": entity_c,
            "eventTime": event_time_utc,
            "revision": row["revision"],
            "text": text_c,
            "_event_dt": event_time_dt,
        })

    # Deduplicate by [entity, eventTime, text] tuple
    dedup_map = {}
    for r in canonicalized_rows:
        key = (r["entity"], r["eventTime"], r["text"])
        if key not in dedup_map:
            dedup_map[key] = []
        dedup_map[key].append(r)

    retained_rows = []
    rejected_rows = []

    for key, group in dedup_map.items():
        group.sort(key=lambda x: (-x["revision"], x["id"].encode('utf-8')))
        winner = group[0]
        retained_rows.append(winner)
        for loser in group[1:]:
            rejected_rows.append({"id": loser["id"], "reasonCodes": ["DUPLICATE"]})

    # Policy checks
    if not policy_valid:
        for r in retained_rows:
            rejected_rows.append({"id": r["id"], "reasonCodes": ["POLICY_INVALID"]})
        retained_rows = []
    else:
        new_retained = []
        for r in retained_rows:
            dt = r["_event_dt"]
            if dt < policy_min_time or dt > policy_max_time:
                rejected_rows.append({"id": r["id"], "reasonCodes": ["OUT_OF_WINDOW"]})
            else:
                new_retained.append(r)
        retained_rows = new_retained

    # Split into train/validation/test
    train_rows = []
    val_rows = []
    test_rows = []

    for r in retained_rows:
        entity_bytes = r["entity"].encode('utf-8')
        h = hashlib.sha256(entity_bytes).digest()
        bucket = h[0] % 10
        if bucket <= 5:
            train_rows.append(r)
        elif bucket <= 7:
            val_rows.append(r)
        else:
            test_rows.append(r)

    # Contamination check
    if policy_valid and contamination_threshold is not None:
        train_word_sets = [extract_words_lc_alnum(r["text"]) for r in train_rows]

        new_val = []
        for r in val_rows:
            r_words = extract_words_lc_alnum(r["text"])
            contaminated = False
            for tw in train_word_sets:
                sim = jaccard_similarity(r_words, tw)
                if sim >= contamination_threshold:
                    contaminated = True
                    break
            if contaminated:
                rejected_rows.append({"id": r["id"], "reasonCodes": ["TRAIN_CONTAMINATION"]})
            else:
                new_val.append(r)
        val_rows = new_val

        new_test = []
        for r in test_rows:
            r_words = extract_words_lc_alnum(r["text"])
            contaminated = False
            for tw in train_word_sets:
                sim = jaccard_similarity(r_words, tw)
                if sim >= contamination_threshold:
                    contaminated = True
                    break
            if contaminated:
                rejected_rows.append({"id": r["id"], "reasonCodes": ["TRAIN_CONTAMINATION"]})
            else:
                new_test.append(r)
        test_rows = new_test

    def make_exact_row_obj(r):
        """Exact key order: id, entity, eventTime, revision, text"""
        return {
            "id": r["id"],
            "entity": r["entity"],
            "eventTime": r["eventTime"],
            "revision": r["revision"],
            "text": r["text"]
        }

    def row_sort_key(r):
        row_obj = make_exact_row_obj(r)
        return (r["id"].encode('utf-8'), raw_compact_json(row_obj).encode('utf-8'))

    train_rows.sort(key=row_sort_key)
    val_rows.sort(key=row_sort_key)
    test_rows.sort(key=row_sort_key)

    def serialize_split(rows):
        serialized_rows = []
        all_bytes = b''
        for r in rows:
            row_obj = make_exact_row_obj(r)
            line = raw_compact_json(row_obj) + '\n'
            all_bytes += line.encode('utf-8')
            serialized_rows.append(row_obj)
        digest = sha256_hex(all_bytes)
        return serialized_rows, digest

    train_serialized, train_digest = serialize_split(train_rows)
    val_serialized, val_digest = serialize_split(val_rows)
    test_serialized, test_digest = serialize_split(test_rows)

    rejected_objects.sort(key=lambda x: ((x["uri"] or "").encode('utf-8'), raw_compact_json(x).encode('utf-8')))

    merged_rejected = {}
    for rr in rejected_rows:
        rid = rr["id"]
        if rid not in merged_rejected:
            merged_rejected[rid] = set()
        merged_rejected[rid].update(rr["reasonCodes"])

    final_rejected_rows = []
    for rid, codes in merged_rejected.items():
        final_rejected_rows.append({"id": rid, "reasonCodes": sorted(list(codes), key=lambda c: c.encode('utf-8'))})
    final_rejected_rows.sort(key=lambda x: (x["id"].encode('utf-8'), raw_compact_json(x).encode('utf-8')))

    lineage_entries.sort(key=lambda x: (x["uri"].encode('utf-8'), raw_compact_json(x).encode('utf-8')))

    return {
        "splits": {
            "train": train_serialized,
            "validation": val_serialized,
            "test": test_serialized
        },
        "rejectedObjects": rejected_objects,
        "rejectedRows": final_rejected_rows,
        "digests": {
            "train": train_digest,
            "validation": val_digest,
            "test": test_digest
        },
        "lineage": lineage_entries
    }, 200


# =============================================================================
# Question 2: BQML Experiment Gate (POST /bqml)
# =============================================================================

BQML_STORE = {}

def evaluate_bqml_select(payload: Dict[str, Any]) -> Any:
    run_id = payload.get("runId")
    if not isinstance(run_id, str) or not run_id or len(run_id) > 128:
        return {"error": "INVALID_INPUT"}, 400

    reason_codes = []
    invalid_input = False

    forbidden_features = payload.get("forbiddenFeatures", [])
    if not isinstance(forbidden_features, list):
        invalid_input = True
    num_trials_limit = payload.get("numTrialsLimit")
    if not is_positive_safe_integer(num_trials_limit):
        invalid_input = True

    rows = payload.get("rows")
    if not isinstance(rows, list) or len(rows) == 0:
        invalid_input = True

    trials = payload.get("trials")
    if not isinstance(trials, list):
        invalid_input = True

    if invalid_input:
        reason_codes.append("INVALID_INPUT")

    input_canonical = sorted_compact_json(payload)

    if run_id in BQML_STORE:
        stored = BQML_STORE[run_id]
        if stored.get("_input_canonical") == input_canonical:
            resp = {k: v for k, v in stored.items() if not k.startswith('_')}
            return resp, 200
        else:
            return {"error": "RUN_ID_CONFLICT"}, 409

    if invalid_input:
        result = {
            "runId": run_id,
            "selectedTrialId": None,
            "trainRowIds": [],
            "evalRowIds": [],
            "featureNames": [],
            "datasetDigest": None,
            "reasonCodes": ["INVALID_INPUT"]
        }
        result["_input_canonical"] = input_canonical
        BQML_STORE[run_id] = result
        return {k: v for k, v in result.items() if not k.startswith('_')}, 200

    # Deduplicate rows by [entity, UTC(eventTime)]
    valid_rows = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        rid = r.get("id")
        entity = r.get("entity")
        et_str = r.get("eventTime")
        pt_str = r.get("predictionTime")
        version = r.get("version")
        split = r.get("split")
        features = r.get("features")

        if not isinstance(rid, str) or not isinstance(entity, str):
            continue
        et_dt = parse_timestamp(et_str) if isinstance(et_str, str) else None
        pt_dt = parse_timestamp(pt_str) if isinstance(pt_str, str) else None
        if et_dt is None or pt_dt is None:
            continue
        if not is_safe_integer(version):
            continue
        if split not in ("TRAIN", "EVAL"):
            continue
        if not isinstance(features, dict):
            continue

        valid_rows.append({
            "id": rid,
            "entity": entity,
            "eventTime_utc": format_utc(et_dt),
            "predictionTime_dt": pt_dt,
            "version": version,
            "split": split,
            "features": features,
            "_et_dt": et_dt
        })

    dedup_map = {}
    for r in valid_rows:
        key = (r["entity"], r["eventTime_utc"])
        if key not in dedup_map:
            dedup_map[key] = []
        dedup_map[key].append(r)

    retained = []
    for key, group in dedup_map.items():
        group.sort(key=lambda x: (-x["version"], x["id"].encode('utf-8')))
        retained.append(group[0])

    # Feature eligibility
    if retained:
        all_feature_names = set()
        for r in retained:
            for fname in r["features"]:
                all_feature_names.add(fname)

        forbidden_set = set(forbidden_features) if isinstance(forbidden_features, list) else set()

        eligible_features = []
        for fname in all_feature_names:
            if fname in forbidden_set:
                continue
            in_all = True
            available_before_pred = True
            for r in retained:
                if fname not in r["features"]:
                    in_all = False
                    break
                feat = r["features"][fname]
                if not isinstance(feat, dict):
                    in_all = False
                    break
                avail_at = feat.get("availableAt")
                if not isinstance(avail_at, str):
                    in_all = False
                    break
                avail_dt = parse_timestamp(avail_at)
                if avail_dt is None:
                    in_all = False
                    break
                if avail_dt > r["predictionTime_dt"]:
                    available_before_pred = False
                    break
            if in_all and available_before_pred:
                eligible_features.append(fname)

        eligible_features.sort(key=lambda x: x.encode('utf-8'))
    else:
        eligible_features = []

    train_ids = sorted([r["id"] for r in retained if r["split"] == "TRAIN"], key=lambda x: x.encode('utf-8'))
    eval_ids = sorted([r["id"] for r in retained if r["split"] == "EVAL"], key=lambda x: x.encode('utf-8'))

    # Exact key order: trainRowIds, evalRowIds, featureNames
    digest_obj = {
        "trainRowIds": train_ids,
        "evalRowIds": eval_ids,
        "featureNames": eligible_features
    }
    dataset_digest = sha256_hex(raw_compact_json(digest_obj).encode('utf-8'))

    if isinstance(trials, list) and len(trials) > num_trials_limit:
        reason_codes.append("TRIAL_LIMIT_EXCEEDED")

    eligible_trials = []
    if isinstance(trials, list):
        for t in trials:
            if not isinstance(t, dict):
                continue
            tid = t.get("trialId")
            status = t.get("status")
            metric = t.get("evalMetric")
            if status == "SUCCEEDED" and is_finite_number(metric) and not isinstance(metric, bool) and is_safe_integer(tid):
                eligible_trials.append({"trialId": tid, "evalMetric": metric})

    selected_trial_id = None
    if eligible_trials and not reason_codes:
        eligible_trials.sort(key=lambda x: (-x["evalMetric"], x["trialId"]))
        selected_trial_id = eligible_trials[0]["trialId"]

    if not eligible_trials and "TRIAL_LIMIT_EXCEEDED" not in reason_codes:
        reason_codes.append("NO_SUCCESSFUL_TRIAL")

    if reason_codes:
        selected_trial_id = None

    reason_codes = sorted(list(set(reason_codes)), key=lambda c: c.encode('utf-8'))

    result = {
        "runId": run_id,
        "selectedTrialId": selected_trial_id,
        "trainRowIds": train_ids,
        "evalRowIds": eval_ids,
        "featureNames": eligible_features,
        "datasetDigest": dataset_digest if not any(c in reason_codes for c in ["INVALID_INPUT"]) else None,
        "reasonCodes": reason_codes
    }
    result["_input_canonical"] = input_canonical
    BQML_STORE[run_id] = result
    return {k: v for k, v in result.items() if not k.startswith('_')}, 200

def evaluate_bqml_evaluate(payload: Dict[str, Any]) -> Any:
    run_id = payload.get("runId")
    if not isinstance(run_id, str) or not run_id:
        return {"error": "INVALID_INPUT"}, 400

    selected_trial_id = payload.get("selectedTrialId")
    dataset_digest = payload.get("datasetDigest")
    metric_floor = payload.get("metricFloor")
    required_slices = payload.get("requiredSlices", {})
    rows = payload.get("rows", [])
    bytes_processed = payload.get("bytesProcessed")
    max_bytes = payload.get("maxBytes")

    reason_codes = []
    invalid_input = False
    invalid_lineage = False

    if run_id not in BQML_STORE:
        invalid_lineage = True
    else:
        stored = BQML_STORE[run_id]
        stored_trial = stored.get("selectedTrialId")
        stored_digest = stored.get("datasetDigest")
        if stored_trial is None or stored_digest is None:
            invalid_lineage = True
        elif selected_trial_id != stored_trial:
            invalid_lineage = True
        elif not isinstance(dataset_digest, str) or len(dataset_digest) != 64 or not re.match(r'^[0-9a-f]{64}$', dataset_digest):
            invalid_lineage = True
        elif dataset_digest != stored_digest:
            invalid_lineage = True

    if invalid_lineage:
        reason_codes.append("INVALID_LINEAGE")

    if not is_finite_number(metric_floor) or isinstance(metric_floor, bool) or not (0 <= metric_floor <= 1):
        invalid_input = True

    if not isinstance(required_slices, dict):
        invalid_input = True
    else:
        for k, v in required_slices.items():
            if not isinstance(k, str) or not is_finite_number(v) or isinstance(v, bool) or not (0 <= v <= 1):
                invalid_input = True
                break

    if not isinstance(rows, list):
        invalid_input = True

    if not is_safe_integer(bytes_processed) or not is_safe_integer(max_bytes):
        invalid_input = True

    if invalid_input:
        reason_codes.append("INVALID_INPUT")

    has_invalid_row = False
    valid_rows = []
    if isinstance(rows, list):
        for r in rows:
            if not isinstance(r, dict):
                has_invalid_row = True
                continue
            label = r.get("label")
            prediction = r.get("prediction")
            slc = r.get("slice")
            if not isinstance(slc, str) or not slc:
                has_invalid_row = True
                continue
            if label not in (0, 1) or prediction not in (0, 1):
                has_invalid_row = True
                continue
            if isinstance(label, bool) or isinstance(prediction, bool):
                has_invalid_row = True
                continue
            valid_rows.append(r)

        if has_invalid_row:
            reason_codes.append("INVALID_TEST_ROW")

    rows_empty_or_invalid = len(rows) == 0 or has_invalid_row if isinstance(rows, list) else True

    test_metric = None
    critical_slice_pass = True

    if rows_empty_or_invalid:
        test_metric = None
        critical_slice_pass = False
    else:
        if valid_rows:
            correct = sum(1 for r in valid_rows if r["label"] == r["prediction"])
            agg_acc = round(correct / len(valid_rows), 12)
            test_metric = agg_acc
        else:
            test_metric = None

        if test_metric is not None and not invalid_input and is_finite_number(metric_floor):
            if test_metric < metric_floor:
                reason_codes.append("AGGREGATE_FLOOR")

        if isinstance(required_slices, dict) and not invalid_input:
            for slice_name, floor in required_slices.items():
                slice_rows = [r for r in valid_rows if r.get("slice") == slice_name]
                if not slice_rows:
                    reason_codes.append(f"MISSING_SLICE:{slice_name}")
                    critical_slice_pass = False
                else:
                    slice_correct = sum(1 for r in slice_rows if r["label"] == r["prediction"])
                    slice_acc = round(slice_correct / len(slice_rows), 12)
                    if slice_acc < floor:
                        reason_codes.append(f"SLICE_FLOOR:{slice_name}")
                        critical_slice_pass = False

    if not invalid_input and is_safe_integer(bytes_processed) and is_safe_integer(max_bytes):
        if bytes_processed > max_bytes:
            reason_codes.append("BYTE_LIMIT")

    if invalid_lineage or invalid_input or has_invalid_row:
        critical_slice_pass = False

    reason_codes = sorted(list(set(reason_codes)), key=lambda c: c.encode('utf-8'))
    decision = "admit" if not reason_codes else "reject"

    return {
        "runId": run_id,
        "selectedTrialId": selected_trial_id,
        "datasetDigest": dataset_digest,
        "testMetric": test_metric,
        "criticalSlicePass": critical_slice_pass,
        "decision": decision,
        "bytesProcessed": bytes_processed,
        "reasonCodes": reason_codes
    }, 200

def evaluate_bqml(payload: Dict[str, Any]) -> Any:
    if not isinstance(payload, dict):
        return {"error": "INVALID_INPUT"}, 400
    phase = payload.get("phase")
    if phase == "select":
        return evaluate_bqml_select(payload)
    elif phase == "evaluate":
        return evaluate_bqml_evaluate(payload)
    else:
        return {"error": "INVALID_INPUT"}, 400


# =============================================================================
# Question 3: Promote (POST /promote)
# =============================================================================

def is_canonical_version(v_str) -> bool:
    if not isinstance(v_str, str):
        return False
    if not v_str.isdigit():
        return False
    if len(v_str) > 1 and v_str[0] == '0':
        return False
    val = int(v_str)
    return val > 0 and val <= 2**53 - 1

def evaluate_promote(payload: Dict[str, Any]) -> Any:
    if not isinstance(payload, dict):
        return {"error": "INVALID_INPUT"}, 400

    policy = payload.get("policy")
    versions = payload.get("versions")
    champion_version = payload.get("championVersion")
    as_of_str = payload.get("asOf")

    if policy is None or not isinstance(policy, dict):
        return {"error": "INVALID_INPUT"}, 400
    if not isinstance(versions, list):
        return {"error": "INVALID_INPUT"}, 400
    if not isinstance(champion_version, str):
        return {"error": "INVALID_INPUT"}, 400

    as_of_dt = parse_timestamp(as_of_str) if isinstance(as_of_str, str) else None

    failed_gates = {}

    dataset_digest = policy.get("datasetDigest")
    schema_digest = policy.get("schemaDigest")
    max_age = policy.get("maxAgeSeconds")
    accuracy_floor = policy.get("accuracyFloor")
    required_slices = policy.get("requiredSlices", {})
    max_latency = policy.get("maxLatencyMs")
    max_size = policy.get("maxSizeBytes")
    min_improvement = policy.get("minImprovement")

    policy_valid = True
    if as_of_dt is None:
        policy_valid = False
    if not isinstance(dataset_digest, str) or not dataset_digest:
        policy_valid = False
    if not isinstance(schema_digest, str) or not schema_digest:
        policy_valid = False
    if not is_safe_integer(max_age):
        policy_valid = False
    if not is_finite_number(accuracy_floor) or isinstance(accuracy_floor, bool) or not (0 <= accuracy_floor <= 1):
        policy_valid = False
    if not isinstance(required_slices, dict):
        policy_valid = False
    else:
        for k, v in required_slices.items():
            if not isinstance(k, str) or not is_finite_number(v) or isinstance(v, bool) or not (0 <= v <= 1):
                policy_valid = False
                break
    if not is_finite_number(max_latency) or isinstance(max_latency, bool) or max_latency < 0:
        policy_valid = False
    if not is_safe_integer(max_size):
        policy_valid = False
    if not is_finite_number(min_improvement) or isinstance(min_improvement, bool) or not (0 <= min_improvement <= 1):
        policy_valid = False

    version_counts = {}
    for v in versions:
        if isinstance(v, dict) and "version" in v:
            ver = v["version"]
            ver_str = ver if isinstance(ver, str) else str(ver)
            version_counts[ver_str] = version_counts.get(ver_str, 0) + 1

    duplicated_versions = {v for v, count in version_counts.items() if count > 1}

    version_map = {}
    eligible = []

    for v in versions:
        if not isinstance(v, dict):
            continue
        ver = v.get("version")
        ver_str = ver if isinstance(ver, str) else str(ver)

        gates = []

        if not is_canonical_version(ver):
            gates.append("INVALID_VERSION")
        if ver_str in duplicated_versions:
            gates.append("DUPLICATE_VERSION")

        if not policy_valid:
            gates.append("INVALID_POLICY")

        ev = v.get("evaluation")
        if not isinstance(ev, dict):
            gates.append("MISSING_EVALUATION")
        else:
            acc = ev.get("accuracy")
            lat = ev.get("latencyMs")
            sz = ev.get("sizeBytes")

            if not is_finite_number(acc) or isinstance(acc, bool) or not is_finite_number(lat) or isinstance(lat, bool) or not is_finite_number(sz) or isinstance(sz, bool):
                gates.append("NON_FINITE")

            if is_finite_number(acc) and not isinstance(acc, bool):
                if not (0 <= acc <= 1):
                    gates.append("METRIC_RANGE")

            created_at_str = ev.get("createdAt")
            created_at_dt = parse_timestamp(created_at_str) if isinstance(created_at_str, str) else None
            if created_at_dt is None:
                gates.append("INVALID_TIMESTAMP")
            elif as_of_dt is not None:
                if created_at_dt > as_of_dt:
                    gates.append("FUTURE_EVALUATION")
                elif policy_valid and (as_of_dt - timedelta(seconds=max_age)) > created_at_dt:
                    gates.append("STALE_EVALUATION")

            if ev.get("artifactDigest") != v.get("artifactDigest"):
                gates.append("ARTIFACT_MISMATCH")

            if policy_valid:
                if ev.get("datasetDigest") != dataset_digest:
                    gates.append("DATASET_MISMATCH")
                if ev.get("schemaDigest") != schema_digest:
                    gates.append("SCHEMA_MISMATCH")

                if is_finite_number(acc) and not isinstance(acc, bool) and 0 <= acc <= 1:
                    if acc < accuracy_floor:
                        gates.append("ACCURACY_FLOOR")

                if is_finite_number(lat) and not isinstance(lat, bool):
                    if lat > max_latency:
                        gates.append("LATENCY_LIMIT")

                if is_finite_number(sz) and not isinstance(sz, bool):
                    if sz > max_size:
                        gates.append("SIZE_LIMIT")

                slices_ev = ev.get("slices", {})
                if isinstance(required_slices, dict) and isinstance(slices_ev, dict):
                    for slice_name, floor in required_slices.items():
                        if slice_name not in slices_ev:
                            gates.append(f"MISSING_SLICE:{slice_name}")
                        else:
                            sv = slices_ev[slice_name]
                            if not is_finite_number(sv) or isinstance(sv, bool):
                                gates.append(f"SLICE_RANGE:{slice_name}")
                            elif not (0 <= sv <= 1):
                                gates.append(f"SLICE_RANGE:{slice_name}")
                            elif sv < floor:
                                gates.append(f"SLICE_FLOOR:{slice_name}")

        gates = sorted(list(set(gates)), key=lambda c: c.encode('utf-8'))
        if gates:
            failed_gates[ver_str] = gates
        else:
            eligible.append(ver_str)
            version_map[ver_str] = v

    eligible_versions = []
    for ver in eligible:
        v = version_map[ver]
        ev = v["evaluation"]
        eligible_versions.append({
            "version": ver,
            "accuracy": ev["accuracy"],
            "latencyMs": ev["latencyMs"],
            "sizeBytes": ev["sizeBytes"],
            "numericVersion": int(ver)
        })

    eligible_versions.sort(key=lambda x: (-x["accuracy"], x["latencyMs"], x["sizeBytes"], x["numericVersion"]))
    eligible_version_ids = [e["version"] for e in eligible_versions]

    champion_valid = champion_version in eligible_version_ids

    if not champion_valid or not eligible_versions:
        result = {
            "action": "block",
            "championVersion": champion_version,
            "selectedVersion": None,
            "eligibleVersions": eligible_version_ids,
            "failedGates": failed_gates,
            "aliasMutation": None,
            "evidence": None
        }
        return result, 200

    best = eligible_versions[0]
    champion_data = next((e for e in eligible_versions if e["version"] == champion_version), None)

    if best["version"] == champion_version:
        action = "retain"
        selected = champion_version
        alias_mutation = None
    else:
        improvement = round(best["accuracy"] - champion_data["accuracy"], 12)
        if improvement >= min_improvement:
            action = "promote"
            selected = best["version"]
            alias_mutation = {"alias": "champion", "version": best["version"]}
        else:
            action = "retain"
            selected = champion_version
            alias_mutation = None

    selected_ev = version_map[selected]["evaluation"]

    result = {
        "action": action,
        "championVersion": champion_version,
        "selectedVersion": selected,
        "eligibleVersions": eligible_version_ids,
        "failedGates": failed_gates,
        "aliasMutation": alias_mutation,
        "evidence": selected_ev
    }
    return result, 200


# =============================================================================
# Question 4: Adapt (POST /adapt)
# =============================================================================

INTERVENTION_ORDER = ["prompt_only", "retrieval", "lora", "qlora"]

def evaluate_adapt_choose(payload: Dict[str, Any]) -> Any:
    policy = payload.get("policy")
    candidates = payload.get("candidates")

    if not isinstance(policy, dict) or not isinstance(candidates, list):
        return {"error": "INVALID_INPUT"}, 400

    min_quality = policy.get("minQuality")
    freshness_required = policy.get("freshnessRequired")
    max_latency = policy.get("maxLatencyMs")
    max_memory = policy.get("maxMemoryMb")
    max_labeled = policy.get("maxLabeledExamples")
    max_total_cost = policy.get("maxTotalCost")
    horizon = policy.get("horizonRequests")

    policy_invalid = False
    if not is_finite_number(min_quality) or isinstance(min_quality, bool) or not (0 <= min_quality <= 1):
        policy_invalid = True
    if not isinstance(freshness_required, bool):
        policy_invalid = True
    if not is_finite_number(max_latency) or isinstance(max_latency, bool) or max_latency < 0:
        policy_invalid = True
    if not is_finite_number(max_memory) or isinstance(max_memory, bool) or max_memory < 0:
        policy_invalid = True
    if not is_safe_integer(max_labeled):
        policy_invalid = True
    if not is_finite_number(max_total_cost) or isinstance(max_total_cost, bool) or max_total_cost < 0:
        policy_invalid = True
    if not is_safe_integer(horizon):
        policy_invalid = True

    candidate_map = {}
    for c in candidates:
        if isinstance(c, dict) and isinstance(c.get("name"), str):
            candidate_map[c["name"]] = c

    if set(candidate_map.keys()) != set(INTERVENTION_ORDER) or len(candidates) != 4:
        return {"error": "INVALID_INPUT"}, 400

    eligible = []
    total_costs = {}
    reason_codes_map = {}

    for name in INTERVENTION_ORDER:
        c = candidate_map[name]
        codes = []

        if policy_invalid:
            codes.append("INVALID_INPUT")

        available = c.get("available")
        quality = c.get("quality")
        freshness = c.get("freshness")
        latency = c.get("latencyMs")
        memory = c.get("memoryMb")
        labeled = c.get("labeledExamples")
        one_time = c.get("oneTimeCost")
        recurring = c.get("recurringCost")

        if available is not True:
            codes.append("UNAVAILABLE")

        if is_finite_number(quality) and not isinstance(quality, bool) and not policy_invalid:
            if quality < min_quality:
                codes.append("QUALITY_FLOOR")
        elif not is_finite_number(quality) or isinstance(quality, bool):
            codes.append("INVALID_INPUT")

        if isinstance(freshness, bool) and not policy_invalid:
            if freshness_required and not freshness:
                codes.append("FRESHNESS_REQUIRED")

        if is_finite_number(latency) and not isinstance(latency, bool) and not policy_invalid:
            if latency > max_latency:
                codes.append("LATENCY_LIMIT")

        if is_finite_number(memory) and not isinstance(memory, bool) and not policy_invalid:
            if memory > max_memory:
                codes.append("MEMORY_LIMIT")

        if is_safe_integer(labeled) and not policy_invalid:
            if labeled > max_labeled:
                codes.append("DATA_LIMIT")

        if is_finite_number(one_time) and not isinstance(one_time, bool) and is_finite_number(recurring) and not isinstance(recurring, bool) and is_safe_integer(horizon):
            tc = round(one_time + horizon * recurring, 12)
            total_costs[name] = tc
            if not policy_invalid and tc > max_total_cost:
                codes.append("COST_LIMIT")
        else:
            total_costs[name] = None

        codes = sorted(list(set(codes)), key=lambda c_str: c_str.encode('utf-8'))
        reason_codes_map[name] = codes

        if not codes:
            eligible.append(name)

    selected = None
    for name in INTERVENTION_ORDER:
        if name in eligible:
            selected = name
            break

    return {
        "selected": selected,
        "eligible": [n for n in INTERVENTION_ORDER if n in eligible],
        "totalCosts": total_costs,
        "reasonCodes": reason_codes_map
    }, 200

def evaluate_adapt_repair(payload: Dict[str, Any]) -> Any:
    reason_codes = []

    tokens = payload.get("tokens", [])
    template_apps = payload.get("templateApplications")
    parameters = payload.get("parameters", [])
    allowed_targets = payload.get("allowedTargets", [])
    inference_mode = payload.get("inferenceMode")
    train_row_ids = payload.get("trainRowIds", [])
    eval_row_ids = payload.get("evalRowIds", [])
    dropout_active = payload.get("dropoutActiveDuringEval")
    artifact_files = payload.get("artifactFiles", [])
    base_revision = payload.get("baseRevision")
    dataset_digest = payload.get("datasetDigest")
    code_digest = payload.get("codeDigest")
    config_digest = payload.get("configDigest")
    expected_digests = payload.get("expectedDigests", {})
    micro_batch = payload.get("microBatch")
    grad_accum = payload.get("gradientAccumulation")
    replicas = payload.get("replicas")
    expected_eff_batch = payload.get("expectedEffectiveBatch")
    checkpoint = payload.get("checkpoint", {})
    uninterrupted = payload.get("uninterruptedWeights", [])
    resumed = payload.get("resumedWeights", [])
    resume_tolerance = payload.get("resumeTolerance")

    # Labels
    labels = []
    all_tokens_valid = True
    if not isinstance(tokens, list) or len(tokens) == 0:
        all_tokens_valid = False
        reason_codes.append("INVALID_TOKEN")
    else:
        for t in tokens:
            if not isinstance(t, dict):
                all_tokens_valid = False
                break
            tid = t.get("id")
            role = t.get("role")
            padding = t.get("padding")
            text = t.get("text")
            if not is_safe_integer(tid):
                all_tokens_valid = False
                break
            if role not in ("system", "user", "assistant"):
                all_tokens_valid = False
                break
            if not isinstance(padding, bool):
                all_tokens_valid = False
                break
            if not isinstance(text, str):
                all_tokens_valid = False
                break

        if not all_tokens_valid:
            reason_codes.append("INVALID_TOKEN")

    if all_tokens_valid and isinstance(tokens, list):
        for t in tokens:
            if t["role"] == "assistant" and t["padding"] is False:
                labels.append(t["id"])
            else:
                labels.append(-100)
    else:
        labels = [-100] * len(tokens) if isinstance(tokens, list) else []

    # Template
    template_pass = template_apps == 1
    if not template_pass:
        reason_codes.append("CHAT_TEMPLATE_COUNT")

    # Parameters - LoRA
    trainable_params = []
    trainable_count = 0
    has_lora = False

    if not isinstance(parameters, list) or not isinstance(allowed_targets, list):
        reason_codes.append("INVALID_PARAMETER")
    else:
        allowed_set = set()
        valid_targets = True
        for tg in allowed_targets:
            if not isinstance(tg, str) or not tg or tg in allowed_set:
                valid_targets = False
                break
            allowed_set.add(tg)

        if not valid_targets or len(allowed_targets) == 0:
            reason_codes.append("INVALID_PARAMETER")
        else:
            param_names = set()
            valid_params = True
            for p in parameters:
                if not isinstance(p, dict):
                    valid_params = False
                    break
                pname = p.get("name")
                target = p.get("target")
                numel = p.get("numel")
                if not isinstance(pname, str) or not isinstance(target, str):
                    valid_params = False
                    break
                if not is_positive_safe_integer(numel):
                    valid_params = False
                    break
                if pname in param_names:
                    valid_params = False
                    break
                param_names.add(pname)

            if not valid_params:
                reason_codes.append("INVALID_PARAMETER")
            else:
                for p in parameters:
                    if p["target"] in allowed_set and (p["name"].endswith(".lora_A.weight") or p["name"].endswith(".lora_B.weight")):
                        trainable_params.append(p["name"])
                        trainable_count += p["numel"]
                        has_lora = True

                if not has_lora:
                    reason_codes.append("INVALID_PARAMETER")

                trainable_params.sort(key=lambda x: x.encode('utf-8'))

    peft_config_pass = has_lora and not any(c in reason_codes for c in ["INVALID_PARAMETER"])

    # Inference mode
    if inference_mode is not False:
        reason_codes.append("INFERENCE_MODE")

    # Artifact files
    expected_artifact_files = ["adapter_config.json", "adapter_model.safetensors"]
    adapter_files = []
    if not isinstance(artifact_files, list):
        reason_codes.append("ADAPTER_FILE_SET")
    else:
        sorted_af = sorted(artifact_files, key=lambda x: x.encode('utf-8') if isinstance(x, str) else b'')
        if sorted_af != expected_artifact_files:
            reason_codes.append("ADAPTER_FILE_SET")
        else:
            adapter_files = expected_artifact_files

    if isinstance(artifact_files, list):
        non_adapter = [f for f in artifact_files if f not in expected_artifact_files]
        if non_adapter:
            reason_codes.append("FULL_MODEL_ARTIFACT")

    # Checkpoint
    required_checkpoint_keys = {"model", "optimizer", "scheduler", "step", "rng", "dataPosition"}
    checkpoint_complete = False
    if isinstance(checkpoint, dict) and set(checkpoint.keys()) == required_checkpoint_keys:
        checkpoint_complete = True
    else:
        reason_codes.append("INCOMPLETE_CHECKPOINT")

    # Base revision
    lineage_pass = True
    if not isinstance(base_revision, str) or not re.match(r'^[0-9a-f]{40}$', base_revision):
        reason_codes.append("MUTABLE_BASE_REVISION")
        lineage_pass = False

    # Digests
    digest_fields = [dataset_digest, code_digest, config_digest]
    all_digests_valid = True
    for d in digest_fields:
        if not isinstance(d, str) or not d or not re.match(r'^[0-9a-f]{64}$', d):
            all_digests_valid = False

    if not all_digests_valid:
        if "LINEAGE_MISMATCH" not in reason_codes:
            reason_codes.append("LINEAGE_MISMATCH")
        lineage_pass = False

    if isinstance(expected_digests, dict) and all_digests_valid:
        for k, v in expected_digests.items():
            actual = {"dataset": dataset_digest, "code": code_digest, "config": config_digest}.get(k)
            if actual and actual != v:
                if "LINEAGE_MISMATCH" not in reason_codes:
                    reason_codes.append("LINEAGE_MISMATCH")
                lineage_pass = False

    # Batch
    if is_positive_safe_integer(micro_batch) and is_positive_safe_integer(grad_accum) and is_positive_safe_integer(replicas) and is_positive_safe_integer(expected_eff_batch):
        if micro_batch * grad_accum * replicas != expected_eff_batch:
            reason_codes.append("EFFECTIVE_BATCH_MISMATCH")
    else:
        reason_codes.append("EFFECTIVE_BATCH_MISMATCH")

    # Eval isolation
    eval_isolated = True
    if not isinstance(train_row_ids, list) or not isinstance(eval_row_ids, list):
        reason_codes.append("EVAL_LEAKAGE")
        eval_isolated = False
    elif not train_row_ids or not eval_row_ids:
        reason_codes.append("EVAL_LEAKAGE")
        eval_isolated = False
    else:
        train_set = set()
        eval_set = set()
        for t in train_row_ids:
            if not isinstance(t, str) or not t:
                eval_isolated = False
                break
            train_set.add(t)
        for e in eval_row_ids:
            if not isinstance(e, str) or not e:
                eval_isolated = False
                break
            eval_set.add(e)
        if len(train_set) != len(train_row_ids) or len(eval_set) != len(eval_row_ids):
            eval_isolated = False
        if train_set & eval_set:
            eval_isolated = False

        if not eval_isolated and "EVAL_LEAKAGE" not in reason_codes:
            reason_codes.append("EVAL_LEAKAGE")

    # Dropout
    eval_deterministic = True
    if dropout_active is not False:
        reason_codes.append("EVAL_DROPOUT_ACTIVE")
        eval_deterministic = False

    # Resume
    resume_pass = True
    if not isinstance(uninterrupted, list) or not isinstance(resumed, list):
        reason_codes.append("RESUME_DIVERGENCE")
        resume_pass = False
    elif len(uninterrupted) == 0 or len(resumed) == 0:
        reason_codes.append("RESUME_DIVERGENCE")
        resume_pass = False
    elif len(uninterrupted) != len(resumed):
        reason_codes.append("RESUME_DIVERGENCE")
        resume_pass = False
    else:
        if not is_finite_number(resume_tolerance) or isinstance(resume_tolerance, bool) or resume_tolerance < 0:
            reason_codes.append("RESUME_DIVERGENCE")
            resume_pass = False
        else:
            for a, b in zip(uninterrupted, resumed):
                if not is_finite_number(a) or isinstance(a, bool) or not is_finite_number(b) or isinstance(b, bool):
                    resume_pass = False
                    break
                if abs(a - b) > resume_tolerance:
                    resume_pass = False
                    break
            if not resume_pass:
                reason_codes.append("RESUME_DIVERGENCE")

    reason_codes = sorted(list(set(reason_codes)), key=lambda c: c.encode('utf-8'))

    return {
        "labels": labels,
        "templatePass": template_pass,
        "trainableParams": trainable_params,
        "trainableCount": trainable_count,
        "peftConfigPass": peft_config_pass,
        "adapterFiles": adapter_files,
        "checkpointComplete": checkpoint_complete,
        "lineagePass": lineage_pass,
        "evalIsolated": eval_isolated,
        "evaluationDeterministic": eval_deterministic,
        "resumePass": resume_pass,
        "reasonCodes": reason_codes
    }, 200

def evaluate_adapt(payload: Dict[str, Any]) -> Any:
    if not isinstance(payload, dict):
        return {"error": "INVALID_INPUT"}, 400
    op = payload.get("operation")
    if op == "choose":
        return evaluate_adapt_choose(payload)
    elif op == "repair":
        return evaluate_adapt_repair(payload)
    else:
        return {"error": "INVALID_INPUT"}, 400


# =============================================================================
# Question 5: Quantize (POST /quantize)
# =============================================================================

QUANTIZE_STORE = {}

def evaluate_quantize_freeze(payload: Dict[str, Any]) -> Any:
    freeze_id = payload.get("freezeId")
    if not isinstance(freeze_id, str) or not freeze_id or len(freeze_id) > 128:
        return {"error": "INVALID_INPUT"}, 400

    calibration_digest = payload.get("calibrationDigest")
    tokenizer_digest = payload.get("tokenizerDigest")
    allowed_reasons = payload.get("allowedUnsupportedReasons", [])
    if allowed_reasons is None:
        allowed_reasons = []
    candidates = payload.get("candidates")

    if not isinstance(candidates, list) or len(candidates) == 0:
        return {"error": "INVALID_INPUT"}, 400

    if not isinstance(calibration_digest, str) or not calibration_digest:
        return {"error": "INVALID_INPUT"}, 400
    if not isinstance(tokenizer_digest, str) or not tokenizer_digest:
        return {"error": "INVALID_INPUT"}, 400
    if not isinstance(allowed_reasons, list):
        return {"error": "INVALID_INPUT"}, 400

    ar_set = set()
    for r in allowed_reasons:
        if isinstance(r, str) and r:
            ar_set.add(r)

    cand_names = set()
    results = []
    for c in candidates:
        if not isinstance(c, dict):
            continue
        name = c.get("name")
        if not isinstance(name, str) or not name:
            continue
        cand_names.add(name)

        files = c.get("files")
        loadable = c.get("loadable")
        cal_dig = c.get("calibrationDigest")
        tok_dig = c.get("tokenizerDigest")
        unsup_reason = c.get("unsupportedReason")

        codes = []

        files_valid = True
        if not isinstance(files, dict) or len(files) == 0:
            files_valid = False
            codes.append("INVALID_INPUT")

        if files_valid:
            fnames = set()
            for fname, fval in files.items():
                if not isinstance(fname, str) or not fname:
                    files_valid = False
                    break
                if fname in fnames:
                    files_valid = False
                    break
                fnames.add(fname)
                if not isinstance(fval, str):
                    files_valid = False
                    break

        inventory = []
        total_bytes_val = None
        package_digest = None

        if files_valid:
            for fname in sorted(files.keys(), key=lambda x: x.encode('utf-8')):
                fdata = files[fname].encode('utf-8')
                fbytes = len(fdata)
                fsha = sha256_hex(fdata)
                # Exact key order: name, bytes, sha256
                inventory.append({"name": fname, "bytes": fbytes, "sha256": fsha})
            total_bytes_val = sum(item["bytes"] for item in inventory)
            package_digest = sha256_hex(raw_compact_json(inventory).encode('utf-8'))

        status = "invalid"
        if isinstance(unsup_reason, str) and unsup_reason:
            if unsup_reason in ar_set:
                status = "unsupported"
                codes = []
            else:
                status = "invalid"
                codes.append("UNALLOWED_UNSUPPORTED_REASON")
        else:
            if loadable is not True:
                codes.append("NOT_LOADABLE")
            if cal_dig != calibration_digest:
                codes.append("CALIBRATION_MISMATCH")
            if tok_dig != tokenizer_digest:
                codes.append("TOKENIZER_MISMATCH")

            if not codes and files_valid:
                status = "frozen"
            else:
                status = "invalid"

        if not files_valid:
            inventory = []
            total_bytes_val = None
            package_digest = None

        codes = sorted(list(set(codes)), key=lambda cc: cc.encode('utf-8'))

        results.append({
            "name": name,
            "status": status,
            "inventory": inventory,
            "totalBytes": total_bytes_val,
            "packageDigest": package_digest,
            "reasonCodes": codes
        })

    results.sort(key=lambda x: x["name"].encode('utf-8'))

    input_canonical = sorted_compact_json(payload)

    if freeze_id in QUANTIZE_STORE:
        stored = QUANTIZE_STORE[freeze_id]
        if stored.get("_input_canonical") == input_canonical:
            resp = {k: v for k, v in stored.items() if not k.startswith('_')}
            return resp, 200
        else:
            return {"error": "FREEZE_ID_CONFLICT"}, 409

    resp = {"freezeId": freeze_id, "candidates": results}
    resp["_input_canonical"] = input_canonical
    QUANTIZE_STORE[freeze_id] = resp
    return {k: v for k, v in resp.items() if not k.startswith('_')}, 200

def evaluate_quantize_select(payload: Dict[str, Any]) -> Any:
    freeze_id = payload.get("freezeId")
    if not isinstance(freeze_id, str) or not freeze_id:
        return {"error": "INVALID_INPUT"}, 400

    candidates = payload.get("candidates")
    pol = payload.get("policy")
    latencies = payload.get("latencies", {})
    rows = payload.get("rows")

    if not isinstance(candidates, list) or not isinstance(pol, dict) or not isinstance(rows, list):
        return {"error": "INVALID_INPUT"}, 400

    stored = QUANTIZE_STORE.get(freeze_id)
    if stored is not None:
        stored_candidates = stored.get("candidates", [])
    else:
        stored_candidates = candidates

    max_bytes_p = pol.get("maxBytes")
    agg_floor = pol.get("aggregateFloor")
    req_slices = pol.get("requiredSlices", {})
    max_lat = pol.get("maxLatencyMs")
    cand_order = pol.get("candidateOrder", [])

    if not isinstance(latencies, dict):
        latencies = {}

    results_list = []
    admitted_list = []

    for c in stored_candidates:
        if not isinstance(c, dict):
            continue
        name = c.get("name")
        if not isinstance(name, str):
            continue
        codes = []

        if c.get("status") != "frozen":
            codes.append("NOT_FROZEN")

        tb = None
        inv = c.get("inventory")
        if isinstance(inv, list) and len(inv) > 0:
            tb = sum(item["bytes"] for item in inv if isinstance(item, dict) and "bytes" in item)
        else:
            tb = c.get("totalBytes")

        lat = latencies.get(name) if isinstance(latencies, dict) else None

        preds_valid = True
        correct = 0
        total = 0
        slice_stats = {}

        for r in rows:
            if not isinstance(r, dict):
                preds_valid = False
                continue
            preds = r.get("predictions", {})
            if not isinstance(preds, dict) or name not in preds:
                preds_valid = False
                continue
            p = preds[name]
            label = r.get("label")
            slc = r.get("slice")
            if p not in (0, 1) or isinstance(p, bool):
                preds_valid = False
                continue
            if label not in (0, 1) or isinstance(label, bool):
                preds_valid = False
                continue
            total += 1
            if p == label:
                correct += 1
            if isinstance(slc, str) and slc:
                if slc not in slice_stats:
                    slice_stats[slc] = {"correct": 0, "total": 0}
                slice_stats[slc]["total"] += 1
                if p == label:
                    slice_stats[slc]["correct"] += 1

        if not preds_valid:
            codes.append("INVALID_PREDICTIONS")

        agg = round(correct / total, 12) if total > 0 and preds_valid else None
        slices_result = {}

        if preds_valid and isinstance(req_slices, dict):
            for sn, sf in req_slices.items():
                if sn in slice_stats and slice_stats[sn]["total"] > 0:
                    sa = round(slice_stats[sn]["correct"] / slice_stats[sn]["total"], 12)
                    slices_result[sn] = sa
                    if sa < sf:
                        codes.append(f"SLICE_FLOOR:{sn}")
                else:
                    slices_result[sn] = None
                    codes.append(f"MISSING_SLICE:{sn}")

        if preds_valid and agg is not None and is_finite_number(agg_floor):
            if agg < agg_floor:
                codes.append("AGGREGATE_FLOOR")

        if tb is not None and is_safe_integer(max_bytes_p):
            if tb > max_bytes_p:
                codes.append("SIZE_LIMIT")

        if lat is not None and is_finite_number(max_lat):
            if lat > max_lat:
                codes.append("LATENCY_LIMIT")

        codes = sorted(list(set(codes)), key=lambda cc: cc.encode('utf-8'))
        admitted = len(codes) == 0

        results_list.append({
            "name": name,
            "aggregate": agg,
            "slices": slices_result,
            "totalBytes": tb,
            "latencyMs": lat,
            "admitted": admitted,
            "reasonCodes": codes
        })

        if admitted:
            admitted_list.append({
                "name": name,
                "totalBytes": tb,
                "latencyMs": lat
            })

    order_map = {n: i for i, n in enumerate(cand_order)} if isinstance(cand_order, list) else {}
    results_list.sort(key=lambda x: (order_map.get(x["name"], 999), x["name"].encode('utf-8')))

    selected = None
    package_manifest = None

    if admitted_list:
        admitted_list.sort(key=lambda x: (x["totalBytes"] or float('inf'), x["latencyMs"] or float('inf'), order_map.get(x["name"], 999)))
        selected = admitted_list[0]["name"]
        for c in stored_candidates:
            if isinstance(c, dict) and c.get("name") == selected:
                package_manifest = c
                break

    return {
        "freezeId": freeze_id,
        "selected": selected,
        "results": results_list,
        "packageManifest": package_manifest
    }, 200

def evaluate_quantize(payload: Dict[str, Any]) -> Any:
    if not isinstance(payload, dict):
        return {"error": "INVALID_INPUT"}, 400
    phase = payload.get("phase")
    if phase == "freeze":
        return evaluate_quantize_freeze(payload)
    elif phase == "select":
        return evaluate_quantize_select(payload)
    else:
        return {"error": "INVALID_INPUT"}, 400


# =============================================================================
# Question 6: Pipeline (POST /pipeline)
# =============================================================================

PIPELINE_SESSIONS = {}

DAG_ORDER = ["verify_data", "prepare", "train", "evaluate", "register", "publish"]
DAG_DEPS = {
    "verify_data": [],
    "prepare": ["verify_data"],
    "train": ["prepare"],
    "evaluate": ["train"],
    "register": ["evaluate"],
    "publish": ["register"]
}

INPUT_KEYS = {
    "verify_data": ["generation", "checksum"],
    "prepare": ["canonicalData", "prepareCode", "prepareConfig"],
    "train": [None, "trainCode", "trainConfig", "runtime"],
    "evaluate": [None, "canonicalData", "evaluateCode", "evaluateConfig"],
    "register": [None, "schemaDigest"],
    "publish": [None, "publishConfig"]
}

def get_session_state(session: str) -> dict:
    if session not in PIPELINE_SESSIONS:
        PIPELINE_SESSIONS[session] = {
            "revision": None,
            "inputs": None,
            "inputs_canonical": None,
            "nodes": {},
            "event_ids": {},
        }
    return PIPELINE_SESSIONS[session]

def evaluate_pipeline(payload: Dict[str, Any]) -> Any:
    if not isinstance(payload, dict):
        return {"error": "INVALID_REQUEST"}, 409

    session = payload.get("session")
    if not isinstance(session, str) or not session:
        return {"error": "INVALID_REQUEST"}, 409

    revision = payload.get("revision")
    if not is_positive_safe_integer(revision):
        return {"error": "INVALID_REQUEST"}, 409

    inputs = payload.get("inputs")
    if not isinstance(inputs, dict):
        return {"error": "INVALID_REQUEST"}, 409

    required_inputs = ["generation", "checksum", "canonicalData", "prepareCode", "prepareConfig",
                       "trainCode", "trainConfig", "runtime", "evaluateCode", "evaluateConfig",
                       "schemaDigest", "publishConfig"]
    for ri in required_inputs:
        if ri not in inputs or not isinstance(inputs[ri], str) or not inputs[ri]:
            return {"error": "INVALID_REQUEST"}, 409

    events = payload.get("events", [])
    if not isinstance(events, list):
        return {"error": "INVALID_REQUEST"}, 409

    state = get_session_state(session)
    inputs_canonical = sorted_compact_json(inputs)

    if state["revision"] is not None:
        if revision < state["revision"]:
            pass
        elif revision == state["revision"]:
            if inputs_canonical != state["inputs_canonical"]:
                return {"error": "REVISION_CONFLICT"}, 409
        else:
            state["revision"] = revision
            state["inputs"] = inputs
            state["inputs_canonical"] = inputs_canonical
            for node in DAG_ORDER:
                if node in state["nodes"]:
                    ns = state["nodes"][node]
                    ns["state"] = None
                    ns["attempt"] = None
    else:
        state["revision"] = revision
        state["inputs"] = inputs
        state["inputs_canonical"] = inputs_canonical
        for node in DAG_ORDER:
            state["nodes"][node] = {
                "state": None,
                "attempt": None,
                "key": None,
                "artifact": None,
                "eventId": None,
                "cached_keys": {}
            }

    def compute_key(node):
        inp = state["inputs"]
        key_inputs = INPUT_KEYS[node]
        values = []
        for k in key_inputs:
            if k is None:
                parent = DAG_DEPS[node][0]
                parent_artifact = get_artifact(parent)
                if parent_artifact is None:
                    return None
                values.append(parent_artifact)
            else:
                values.append(inp[k])
        return sha256_hex(raw_compact_json(values).encode('utf-8'))

    def get_artifact(node):
        ns = state["nodes"].get(node, {})
        key = compute_key(node)
        if key and key in ns.get("cached_keys", {}):
            return ns["cached_keys"][key]["artifact"]
        return None

    def is_node_reusable(node):
        key = compute_key(node)
        if key is None:
            return False
        ns = state["nodes"].get(node, {})
        return key in ns.get("cached_keys", {})

    accepted_ids = []
    ignored_ids = []

    for ev in events:
        if not isinstance(ev, dict):
            continue

        ev_id = ev.get("eventId")
        ev_rev = ev.get("revision")
        ev_node = ev.get("node")
        ev_attempt = ev.get("attempt")
        ev_status = ev.get("status")
        ev_key = ev.get("key")
        ev_artifact = ev.get("artifactDigest")
        ev_receipt = ev.get("receiptId")

        required_ev_fields = {"eventId", "revision", "node", "attempt", "status", "key", "artifactDigest", "receiptId"}
        if set(ev.keys()) != required_ev_fields:
            ignored_ids.append(ev_id)
            continue

        ev_canonical = sorted_compact_json(ev)
        if ev_id in state["event_ids"]:
            if state["event_ids"][ev_id] == ev_canonical:
                ignored_ids.append(ev_id)
                continue
            else:
                return {"error": "EVENT_ID_CONFLICT"}, 409

        if ev_rev != state["revision"]:
            ignored_ids.append(ev_id)
            continue

        if ev_node not in DAG_ORDER:
            ignored_ids.append(ev_id)
            continue

        if ev_status not in ("started", "succeeded", "retryable_failed", "terminal_failed"):
            ignored_ids.append(ev_id)
            continue

        if not is_positive_safe_integer(ev_attempt):
            ignored_ids.append(ev_id)
            continue

        if ev_status == "succeeded":
            if not isinstance(ev_artifact, str) or not ev_artifact:
                ignored_ids.append(ev_id)
                continue
        else:
            if ev_artifact is not None:
                ignored_ids.append(ev_id)
                continue

        if ev_status == "succeeded" and ev_node in ("register", "publish"):
            expected_receipt = f"receipt:{ev_node}:{ev_key}"
            if ev_receipt != expected_receipt:
                ignored_ids.append(ev_id)
                continue
        else:
            if ev_receipt is not None:
                ignored_ids.append(ev_id)
                continue

        current_key = compute_key(ev_node)
        if current_key is None or ev_key != current_key:
            ignored_ids.append(ev_id)
            continue

        for dep in DAG_DEPS[ev_node]:
            if not is_node_reusable(dep):
                ignored_ids.append(ev_id)
                continue

        ns = state["nodes"][ev_node]

        current_state = ns.get("state")
        current_attempt = ns.get("attempt")

        if current_key in ns.get("cached_keys", {}):
            if ev_status == "succeeded" and ev_artifact != ns["cached_keys"][current_key]["artifact"]:
                return {"error": "EVIDENCE_CONFLICT"}, 409
            else:
                if ev_status == "succeeded":
                    ignored_ids.append(ev_id)
                    continue
                else:
                    return {"error": "STATUS_CONFLICT"}, 409

        if current_state is None:
            if ev_status == "started" and ev_attempt == 1:
                ns["state"] = "started"
                ns["attempt"] = 1
                ns["key"] = current_key
                ns["eventId"] = ev_id
                state["event_ids"][ev_id] = ev_canonical
                accepted_ids.append(ev_id)
            else:
                ignored_ids.append(ev_id)
        elif current_state == "started":
            if ev_attempt == current_attempt:
                if ev_status in ("succeeded", "retryable_failed", "terminal_failed"):
                    if ev_status == "succeeded":
                        ns["state"] = "succeeded"
                        ns["artifact"] = ev_artifact
                        if "cached_keys" not in ns:
                            ns["cached_keys"] = {}
                        ns["cached_keys"][current_key] = {"artifact": ev_artifact, "eventId": ev_id}
                    elif ev_status == "retryable_failed":
                        ns["state"] = "retryable_failed"
                    elif ev_status == "terminal_failed":
                        ns["state"] = "terminal_failed"
                    ns["eventId"] = ev_id
                    state["event_ids"][ev_id] = ev_canonical
                    accepted_ids.append(ev_id)
                else:
                    return {"error": "STATUS_CONFLICT"}, 409
            elif ev_attempt < current_attempt:
                ignored_ids.append(ev_id)
            else:
                return {"error": "STATUS_CONFLICT"}, 409
        elif current_state == "retryable_failed":
            if ev_status == "started" and ev_attempt == current_attempt + 1:
                ns["state"] = "started"
                ns["attempt"] = ev_attempt
                ns["eventId"] = ev_id
                state["event_ids"][ev_id] = ev_canonical
                accepted_ids.append(ev_id)
            elif ev_attempt <= current_attempt:
                ignored_ids.append(ev_id)
            else:
                return {"error": "STATUS_CONFLICT"}, 409
        elif current_state == "terminal_failed":
            return {"error": "STATUS_CONFLICT"}, 409
        elif current_state == "succeeded":
            if ev_status == "succeeded" and ev_artifact != ns.get("artifact"):
                return {"error": "EVIDENCE_CONFLICT"}, 409
            else:
                return {"error": "STATUS_CONFLICT"}, 409

    nodes_response = []
    for node in DAG_ORDER:
        ns = state["nodes"][node]
        current_key = compute_key(node)

        dep_digests = {}
        inp = state["inputs"]
        key_inputs = INPUT_KEYS[node]
        input_names = []
        if node == "verify_data":
            input_names = ["generation", "checksum"]
        elif node == "prepare":
            input_names = ["canonicalData", "prepareCode", "prepareConfig"]
        elif node == "train":
            input_names = ["prepareArtifact", "trainCode", "trainConfig", "runtime"]
        elif node == "evaluate":
            input_names = ["trainArtifact", "canonicalData", "evaluateCode", "evaluateConfig"]
        elif node == "register":
            input_names = ["evaluateArtifact", "schemaDigest"]
        elif node == "publish":
            input_names = ["registerArtifact", "publishConfig"]

        for i, kname in enumerate(key_inputs):
            if kname is None:
                parent = DAG_DEPS[node][0]
                dep_digests[input_names[i]] = get_artifact(parent)
            else:
                dep_digests[input_names[i]] = inp[kname]

        dep_digests["cacheKey"] = current_key

        action = "block"
        reason = ["UPSTREAM_PENDING"]
        triggering_ids = []

        if current_key is not None and current_key in ns.get("cached_keys", {}):
            action = "reuse"
            reason = ["CACHE_HIT"]
            triggering_ids = [ns["cached_keys"][current_key]["eventId"]]
        elif ns.get("state") == "terminal_failed":
            action = "block"
            reason = ["TERMINAL_FAILURE"]
            triggering_ids = [ns.get("eventId")]
        elif ns.get("state") == "started":
            action = "block"
            reason = ["RUNNING"]
            triggering_ids = [ns.get("eventId")]
        elif ns.get("state") == "retryable_failed":
            action = "rerun"
            reason = ["RETRYABLE_FAILURE"]
            triggering_ids = []
        elif current_key is not None:
            upstream_ok = True
            upstream_terminal = False
            for dep in DAG_DEPS[node]:
                dep_key = compute_key(dep)
                dep_ns = state["nodes"][dep]
                if dep_key is None or dep_key not in dep_ns.get("cached_keys", {}):
                    upstream_ok = False
                    if dep_ns.get("state") == "terminal_failed":
                        upstream_terminal = True

            if upstream_ok:
                action = "rerun"
                reason = ["CACHE_MISS"]
                triggering_ids = []
            elif upstream_terminal:
                action = "block"
                reason = ["UPSTREAM_TERMINAL"]
                triggering_ids = []
            else:
                action = "block"
                reason = ["UPSTREAM_PENDING"]
                triggering_ids = []
        else:
            upstream_terminal = False
            for dep in DAG_DEPS[node]:
                dep_ns = state["nodes"][dep]
                if dep_ns.get("state") == "terminal_failed":
                    upstream_terminal = True

            if upstream_terminal:
                action = "block"
                reason = ["UPSTREAM_TERMINAL"]
            else:
                action = "block"
                reason = ["UPSTREAM_PENDING"]

        nodes_response.append({
            "node": node,
            "action": action,
            "reasonCodes": reason,
            "dependencyDigests": dep_digests,
            "triggeringEventIds": triggering_ids
        })

    return {
        "revision": state["revision"],
        "acceptedEventIds": accepted_ids,
        "ignoredEventIds": ignored_ids,
        "nodes": nodes_response
    }, 200


# =============================================================================
# Question 7: Verify Bundle (POST /verify-bundle)
# =============================================================================

REQUIRED_BUNDLE_FILES = {"README.md", "training_manifest.json", "evaluation.json", "inventory.json", "adapter_model.safetensors", "adapter_config.json"}

def evaluate_verify_bundle(payload: Dict[str, Any]) -> Any:
    if not isinstance(payload, dict):
        return {"error": "INVALID_INPUT"}, 400

    policy = payload.get("policy")
    files = payload.get("files")

    if not isinstance(policy, dict) or not isinstance(files, dict):
        return {"error": "INVALID_INPUT"}, 400

    violations = []

    req_slices = policy.get("requiredSlices")
    license_val = policy.get("license")
    intended_use = policy.get("intendedUse")
    limitations = policy.get("limitations")

    policy_valid = True
    if not isinstance(req_slices, list) or len(req_slices) == 0:
        policy_valid = False
    elif len(set(req_slices)) != len(req_slices):
        policy_valid = False
    else:
        for s in req_slices:
            if not isinstance(s, str) or not s:
                policy_valid = False
                break

    if not isinstance(license_val, str) or not license_val:
        policy_valid = False
    if not isinstance(intended_use, str) or not intended_use:
        policy_valid = False
    if not isinstance(limitations, str) or not limitations:
        policy_valid = False

    if not policy_valid:
        violations.append("INVALID_POLICY")

    for fname in sorted(REQUIRED_BUNDLE_FILES):
        if fname not in files:
            violations.append(f"MISSING_FILE:{fname}")

    extra_files = set(files.keys()) - REQUIRED_BUNDLE_FILES
    if extra_files:
        violations.append("UNTRACKED_FILE")

    unsafe_exts = {".bin", ".pt", ".pth", ".pkl", ".pickle"}
    for fname in files.keys():
        for ext in unsafe_exts:
            if fname.endswith(ext):
                violations.append("UNSAFE_WEIGHTS")
                break
        if "UNSAFE_WEIGHTS" in violations:
            break

    computed_inventory = []
    for fname in sorted(files.keys(), key=lambda x: x.encode('utf-8')):
        if fname == "inventory.json":
            continue
        fdata = files[fname].encode('utf-8') if isinstance(files[fname], str) else b''
        # Exact key order: name, bytes, sha256
        computed_inventory.append({
            "name": fname,
            "bytes": len(fdata),
            "sha256": sha256_hex(fdata)
        })

    inventory_digest = sha256_hex(raw_compact_json(computed_inventory).encode('utf-8'))

    if "inventory.json" in files:
        try:
            inv_parsed = json.loads(files["inventory.json"])
            if raw_compact_json(inv_parsed) != raw_compact_json(computed_inventory):
                violations.append("INVENTORY_MISMATCH")
        except Exception:
            violations.append("INVALID_JSON:inventory.json")

    adapter_config = None
    if "adapter_config.json" in files:
        try:
            adapter_config = json.loads(files["adapter_config.json"])
            if not isinstance(adapter_config, dict):
                violations.append("INVALID_ADAPTER_CONFIG")
                adapter_config = None
            else:
                r_val = adapter_config.get("r")
                target_modules = adapter_config.get("target_modules")
                if not is_positive_safe_integer(r_val):
                    violations.append("INVALID_ADAPTER_CONFIG")
                if not isinstance(target_modules, list) or len(target_modules) == 0 or len(set(target_modules)) != len(target_modules):
                    violations.append("INVALID_ADAPTER_CONFIG")
                else:
                    for tm in target_modules:
                        if not isinstance(tm, str) or not tm:
                            violations.append("INVALID_ADAPTER_CONFIG")
                            break
        except Exception:
            violations.append("INVALID_JSON:adapter_config.json")

    manifest = None
    model_artifact_digest = None
    eval_artifact_digest = None

    if "training_manifest.json" in files:
        try:
            manifest = json.loads(files["training_manifest.json"])
            if not isinstance(manifest, dict):
                violations.append("INVALID_TRAINING_MANIFEST")
                manifest = None
            else:
                base_rev = manifest.get("baseRevision")
                if not isinstance(base_rev, str) or not re.match(r'^[0-9a-f]{40}$', base_rev):
                    violations.append("MUTABLE_BASE_REVISION")

                required_manifest_fields = ["task", "datasetDigest", "codeDigest", "trainingConfigDigest", "modelArtifactDigest", "evaluationArtifactDigest"]
                for f in required_manifest_fields:
                    if f not in manifest or not isinstance(manifest[f], str) or not manifest[f]:
                        violations.append(f"MISSING_MANIFEST_FIELD:{f}")

                if "adapter_model.safetensors" in files:
                    model_artifact_digest = sha256_hex(files["adapter_model.safetensors"].encode('utf-8'))
                    if manifest.get("modelArtifactDigest") != model_artifact_digest:
                        violations.append("MODEL_ARTIFACT_MISMATCH")

                if "evaluation.json" in files:
                    eval_artifact_digest = sha256_hex(files["evaluation.json"].encode('utf-8'))
                    if manifest.get("evaluationArtifactDigest") != eval_artifact_digest:
                        violations.append("EVALUATION_DIGEST_MISMATCH")

        except Exception:
            violations.append("INVALID_JSON:training_manifest.json")

    evaluation = None
    if "evaluation.json" in files:
        try:
            evaluation = json.loads(files["evaluation.json"])
            if not isinstance(evaluation, dict):
                violations.append("INVALID_EVALUATION")
                evaluation = None
            else:
                if model_artifact_digest and evaluation.get("modelArtifactDigest") != model_artifact_digest:
                    violations.append("EVALUATION_ARTIFACT_MISMATCH")

                agg = evaluation.get("aggregate")
                if not is_finite_number(agg) or isinstance(agg, bool) or not (0 <= agg <= 1):
                    violations.append("INVALID_AGGREGATE")

                if policy_valid:
                    slices = evaluation.get("slices", {})
                    if isinstance(slices, dict):
                        for sn in req_slices:
                            if sn not in slices:
                                violations.append(f"MISSING_SLICE:{sn}")
                            else:
                                sv = slices[sn]
                                if not is_finite_number(sv) or isinstance(sv, bool) or not (0 <= sv <= 1):
                                    violations.append(f"SLICE_RANGE:{sn}")
        except Exception:
            violations.append("INVALID_JSON:evaluation.json")

    if "README.md" in files:
        readme = files["README.md"]
        marker_prefix = "<!-- tds-model-card "
        marker_suffix = " -->"

        markers = []
        idx = 0
        while True:
            start = readme.find(marker_prefix, idx)
            if start == -1:
                break
            end = readme.find("-->", start + len(marker_prefix))
            if end == -1:
                break
            payload_str = readme[start + len(marker_prefix):end].strip()
            markers.append(payload_str)
            idx = end + 3

        if len(markers) == 0:
            violations.append("MODEL_CARD_COUNT")
            violations.append("MISSING_MODEL_CARD")
        elif len(markers) > 1:
            violations.append("MODEL_CARD_COUNT")
        else:
            try:
                card = json.loads(markers[0])
                if not isinstance(card, dict):
                    violations.append("INVALID_MODEL_CARD")
                else:
                    mismatches = False
                    if manifest:
                        if card.get("task") != manifest.get("task"):
                            mismatches = True
                        if card.get("baseRevision") != manifest.get("baseRevision"):
                            mismatches = True
                        if card.get("datasetDigest") != manifest.get("datasetDigest"):
                            mismatches = True
                        if card.get("modelArtifactDigest") != manifest.get("modelArtifactDigest"):
                            mismatches = True
                    if policy_valid:
                        if card.get("license") != license_val:
                            mismatches = True
                        if card.get("intendedUse") != intended_use:
                            mismatches = True
                        if card.get("limitations") != limitations:
                            mismatches = True
                    if mismatches:
                        violations.append("MODEL_CARD_MISMATCH")
            except Exception:
                violations.append("INVALID_MODEL_CARD")

    violations = sorted(list(set(violations)), key=lambda c: c.encode('utf-8'))
    decision = "admit" if not violations else "reject"

    return {
        "decision": decision,
        "violations": violations,
        "inventoryDigest": inventory_digest
    }, 200
