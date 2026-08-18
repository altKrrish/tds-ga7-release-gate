"""Quick smoke tests for all 7 new endpoints."""
import urllib.request
import json
import sys
import hashlib

sys.stdout.reconfigure(encoding='utf-8')

BASE = "http://localhost:8000"

def post(path, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(f"{BASE}{path}", data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        resp = urllib.request.urlopen(req)
        return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())

def test_build_corpus():
    # Test with a valid object
    content = json.dumps({"id":"r1","entity":"Test Entity","eventTime":"2024-06-15T12:00:00Z","revision":1,"text":"Hello world test"})
    import struct
    # Compute CRC32C
    def crc32c_py(data):
        table = []
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1: crc = (crc >> 1) ^ 0x82F63B78
                else: crc >>= 1
            table.append(crc)
        crc = 0xFFFFFFFF
        for b in data:
            crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
        return crc ^ 0xFFFFFFFF

    content_bytes = content.encode('utf-8')
    crc = crc32c_py(content_bytes)
    crc_hex = f"{crc:08x}"

    status, resp = post("/build-corpus", {
        "policy": {"minTime": "2024-01-01T00:00:00Z", "maxTime": "2025-01-01T00:00:00Z", "contaminationThreshold": 0.8},
        "objects": [{
            "uri": "gs://bucket/obj1",
            "generation": "123",
            "fetchedGeneration": "123",
            "crc32c": crc_hex,
            "schemaId": "training-v1",
            "content": content
        }]
    })
    assert status == 200, f"build-corpus: {status}"
    assert "splits" in resp, f"build-corpus missing splits: {resp}"
    assert "digests" in resp, f"build-corpus missing digests: {resp}"
    total_rows = len(resp["splits"]["train"]) + len(resp["splits"]["validation"]) + len(resp["splits"]["test"])
    assert total_rows == 1, f"build-corpus: expected 1 row, got {total_rows}"
    print(f"✓ build-corpus: {status}, {total_rows} row in splits")

def test_bqml():
    # Test select phase
    status, resp = post("/bqml", {
        "phase": "select",
        "runId": "test-run-1",
        "forbiddenFeatures": [],
        "numTrialsLimit": 10,
        "rows": [{
            "id": "row1", "entity": "e1", "eventTime": "2024-06-15T12:00:00Z",
            "predictionTime": "2024-06-16T12:00:00Z", "version": 1,
            "split": "TRAIN",
            "features": {"f1": {"availableAt": "2024-06-14T12:00:00Z"}}
        }],
        "trials": [{"trialId": 1, "status": "SUCCEEDED", "evalMetric": 0.9}]
    })
    assert status == 200, f"bqml select: {status}"
    assert resp.get("selectedTrialId") == 1, f"bqml: unexpected trial: {resp}"
    print(f"✓ bqml select: {status}, selectedTrialId={resp.get('selectedTrialId')}")

    # Test evaluate phase
    status2, resp2 = post("/bqml", {
        "phase": "evaluate",
        "runId": "test-run-1",
        "selectedTrialId": 1,
        "datasetDigest": resp["datasetDigest"],
        "metricFloor": 0.5,
        "requiredSlices": {},
        "rows": [{"label": 1, "prediction": 1, "slice": "all"}, {"label": 0, "prediction": 0, "slice": "all"}],
        "bytesProcessed": 100,
        "maxBytes": 1000
    })
    assert status2 == 200, f"bqml evaluate: {status2}"
    print(f"✓ bqml evaluate: {status2}, decision={resp2.get('decision')}, testMetric={resp2.get('testMetric')}")

def test_promote():
    status, resp = post("/promote", {
        "asOf": "2024-06-15T12:00:00Z",
        "championVersion": "1",
        "policy": {
            "datasetDigest": "abc123", "schemaDigest": "def456",
            "maxAgeSeconds": 86400, "accuracyFloor": 0.5,
            "requiredSlices": {}, "maxLatencyMs": 200,
            "maxSizeBytes": 10000000, "minImprovement": 0.01
        },
        "versions": [{
            "version": "1", "artifactDigest": "art1",
            "tags": {},
            "evaluation": {
                "createdAt": "2024-06-15T11:00:00Z",
                "artifactDigest": "art1", "datasetDigest": "abc123", "schemaDigest": "def456",
                "accuracy": 0.9, "latencyMs": 50, "sizeBytes": 500000,
                "slices": {}
            }
        }]
    })
    assert status == 200, f"promote: {status}"
    print(f"✓ promote: {status}, action={resp.get('action')}")

def test_adapt_choose():
    candidates = []
    for name in ["prompt_only", "retrieval", "lora", "qlora"]:
        candidates.append({
            "name": name, "available": True, "quality": 0.85,
            "freshness": True, "latencyMs": 50, "memoryMb": 256,
            "labeledExamples": 0, "oneTimeCost": 10, "recurringCost": 0.01
        })
    status, resp = post("/adapt", {
        "operation": "choose",
        "policy": {
            "minQuality": 0.8, "freshnessRequired": True,
            "maxLatencyMs": 100, "maxMemoryMb": 1024,
            "maxLabeledExamples": 100, "maxTotalCost": 1000,
            "horizonRequests": 10000
        },
        "candidates": candidates
    })
    assert status == 200, f"adapt choose: {status}"
    assert resp.get("selected") == "prompt_only", f"adapt: unexpected selection: {resp.get('selected')}"
    print(f"✓ adapt choose: {status}, selected={resp.get('selected')}")

def test_quantize():
    status, resp = post("/quantize", {
        "phase": "freeze",
        "freezeId": "test-freeze-1",
        "calibrationDigest": "cal123",
        "tokenizerDigest": "tok456",
        "allowedUnsupportedReasons": ["custom_op"],
        "candidates": [{
            "name": "q4",
            "files": {"model.bin": "test data"},
            "loadable": True,
            "calibrationDigest": "cal123",
            "tokenizerDigest": "tok456",
            "unsupportedReason": None
        }]
    })
    assert status == 200, f"quantize freeze: {status}"
    print(f"✓ quantize freeze: {status}, candidates={len(resp.get('candidates', []))}")

def test_pipeline():
    status, resp = post("/pipeline", {
        "session": "test-session-1",
        "revision": 1,
        "inputs": {
            "generation": "g1", "checksum": "c1",
            "canonicalData": "cd1", "prepareCode": "pc1", "prepareConfig": "pcf1",
            "trainCode": "tc1", "trainConfig": "tcf1", "runtime": "rt1",
            "evaluateCode": "ec1", "evaluateConfig": "ecf1",
            "schemaDigest": "sd1", "publishConfig": "pub1"
        },
        "events": []
    })
    assert status == 200, f"pipeline: {status}"
    assert len(resp.get("nodes", [])) == 6, f"pipeline: expected 6 nodes, got {len(resp.get('nodes', []))}"
    print(f"✓ pipeline: {status}, nodes={len(resp.get('nodes', []))}")

def test_verify_bundle():
    import hashlib
    adapter_data = "fake adapter weights"
    eval_data = json.dumps({"aggregate": 0.9, "slices": {"critical": 0.85}, "modelArtifactDigest": hashlib.sha256(adapter_data.encode()).hexdigest()})
    model_digest = hashlib.sha256(adapter_data.encode()).hexdigest()
    eval_digest = hashlib.sha256(eval_data.encode()).hexdigest()

    manifest = json.dumps({
        "task": "classification",
        "baseRevision": "a" * 40,
        "datasetDigest": "d" * 64,
        "codeDigest": "c" * 64,
        "trainingConfigDigest": "t" * 64,
        "modelArtifactDigest": model_digest,
        "evaluationArtifactDigest": eval_digest
    })

    readme = f'<!-- tds-model-card {json.dumps({"task":"classification","baseRevision":"a"*40,"datasetDigest":"d"*64,"modelArtifactDigest":model_digest,"license":"MIT","intendedUse":"testing","limitations":"none"})} -->'

    files_dict = {
        "adapter_model.safetensors": adapter_data,
        "adapter_config.json": json.dumps({"r": 16, "target_modules": ["q_proj"]}),
        "training_manifest.json": manifest,
        "evaluation.json": eval_data,
        "README.md": readme,
    }

    # Compute inventory
    inv = []
    for fname in sorted(files_dict.keys(), key=lambda x: x.encode('utf-8')):
        if fname == "inventory.json":
            continue
        fb = files_dict[fname].encode('utf-8')
        inv.append({"name": fname, "bytes": len(fb), "sha256": hashlib.sha256(fb).hexdigest()})

    files_dict["inventory.json"] = json.dumps(inv, ensure_ascii=False, separators=(',', ':'))

    status, resp = post("/verify-bundle", {
        "policy": {"requiredSlices": ["critical"], "license": "MIT", "intendedUse": "testing", "limitations": "none"},
        "files": files_dict
    })
    assert status == 200, f"verify-bundle: {status}"
    print(f"✓ verify-bundle: {status}, decision={resp.get('decision')}, violations={resp.get('violations')}")

if __name__ == "__main__":
    tests = [
        ("build-corpus", test_build_corpus),
        ("bqml", test_bqml),
        ("promote", test_promote),
        ("adapt choose", test_adapt_choose),
        ("quantize", test_quantize),
        ("pipeline", test_pipeline),
        ("verify-bundle", test_verify_bundle),
    ]
    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
            passed += 1
        except Exception as e:
            print(f"✗ {name}: {e}")
            failed += 1

    print(f"\n{passed}/{passed+failed} tests passed")
