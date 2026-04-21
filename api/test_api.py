"""
FedGate API test script — Phase 5

Tests all endpoints by importing and calling the functions directly.
No running server required. Run from any working directory.
"""

import sys
import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, os.path.join(ROOT_DIR, 'api'))

# ---------------------------------------------------------------------------
# Test 1 — Import check
# ---------------------------------------------------------------------------
print('Test 1 — Import check')
from main import app, root, get_node_status, get_epsilon_results, get_poison_demo, get_federation_status, run_federation_endpoint, FederationRequest
print('  All endpoints imported successfully')

# ---------------------------------------------------------------------------
# Test 2 — Root endpoint
# ---------------------------------------------------------------------------
print('Test 2 — Root endpoint')
response = root()
assert response['status'] == 'success', f"Expected success, got {response['status']}"
assert 'FedGate' in response['data']['service'], "Service name missing"
print(f'  Service: {response["data"]["service"]} ✓')

# ---------------------------------------------------------------------------
# Test 3 — Node status when no federation has run
# ---------------------------------------------------------------------------
print('Test 3 — Node status (no prior run)')
response = get_node_status()
assert response['status'] == 'success', f"Expected success, got {response['status']}"
assert response['data']['federation_status'] == 'idle', f"Expected idle, got {response['data']['federation_status']}"
print(f'  Status: {response["data"]["federation_status"]} ✓')

# ---------------------------------------------------------------------------
# Test 4 — Epsilon results
# ---------------------------------------------------------------------------
print('Test 4 — Epsilon results')
response = get_epsilon_results()
if response['status'] == 'success':
    assert 'results' in response['data'], "Missing results field"
    assert 'key_finding' in response['data'], "Missing key_finding field"
    assert len(response['data']['results']) == 6, f"Expected 6 results, got {len(response['data']['results'])}"
    print(f'  Epsilon values found: {len(response["data"]["results"])} ✓')
    print(f'  Key finding: {response["data"]["key_finding"][:80]}...')
    # Check interpretation labels are attached
    for r in response['data']['results']:
        assert 'interpretation' in r, f"Missing interpretation on epsilon={r['epsilon']}"
    print(f'  Interpretation labels: all present ✓')
else:
    print(f'  WARNING: {response["data"]["error"]} — run epsilon_sweep.py first')

# ---------------------------------------------------------------------------
# Test 5 — Poison demo
# ---------------------------------------------------------------------------
print('Test 5 — Poison demo results')
response = get_poison_demo()
if response['status'] == 'success':
    assert 'with_reputation' in response['data'], "Missing with_reputation field"
    assert 'without_reputation' in response['data'], "Missing without_reputation field"
    assert 'key_finding' in response['data'], "Missing key_finding field"
    print(f'  Poison demo data found ✓')
    print(f'  F1 defended: {response["data"].get("f1_defended", "N/A")}')
else:
    print(f'  WARNING: {response["data"]["error"]} — run poison_demo.py first')

# ---------------------------------------------------------------------------
# Test 6 — Quick federation run (3 rounds)
# ---------------------------------------------------------------------------
print('Test 6 — Quick federation run (3 rounds)')
request = FederationRequest(num_rounds=3, epsilon=1.0, use_reputation=True)
response = run_federation_endpoint(request)
assert response['status'] == 'success', f"Expected success, got {response['status']}"
assert len(response['data']['convergence_curve']) == 3, \
    f"Expected 3 convergence entries, got {len(response['data']['convergence_curve'])}"
assert response['data']['mean_improvement'] is not None, "Missing mean_improvement"
print(f'  Federation completed ✓')
print(f'  Mean improvement: {response["data"]["mean_improvement"]:+.4f}')
print(f'  Convergence: {[round(r["mean_global_f1"], 3) for r in response["data"]["convergence_curve"]]}')
print(f'  Summary: {response["data"]["summary"]}')

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
print('\nAll API tests passed. Run the server with:')
print('  cd api && python main.py')
print('  or: uvicorn api.main:app --reload --port 8000')
print('\nAPI docs available at: http://localhost:8000/docs')
