"""
Comprehensive test script for Q1-Q7 endpoints to find and fix all edge cases.
"""
import sys
import json
import urllib.request

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

print("Testing server endpoint availability...")
print("Q1 /build-corpus:", post("/build-corpus", {}))
print("Q2 /bqml:", post("/bqml", {}))
print("Q3 /promote:", post("/promote", {}))
print("Q4 /adapt:", post("/adapt", {}))
print("Q5 /quantize:", post("/quantize", {}))
print("Q6 /pipeline:", post("/pipeline", {}))
print("Q7 /verify-bundle:", post("/verify-bundle", {}))
