#!/usr/bin/env bash
# Verify Zenodo folding stack on array-firewall (18728103 checklist slice).
set -euo pipefail

API="${ARRAY_FW_API_URL:-http://127.0.0.1:8090}"
TOKEN_FILE="${ARRAY_FW_TOKEN_FILE:-/etc/array-firewall/api.token}"
HDR=()
if [[ -f "$TOKEN_FILE" ]]; then
  TOKEN="$(tr -d '\n' < "$TOKEN_FILE")"
  HDR=(-H "Authorization: Bearer $TOKEN")
fi

pass() { echo "OK  $*"; }
fail() { echo "FAIL $*" >&2; exit 1; }

echo "==> GET $API/api/v1/folding/status"
st="$(curl -sfS "${HDR[@]}" "$API/api/v1/folding/status")" || fail "folding status"
echo "$st" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('ok'); print('fold_dim', d.get('fold_dim'), 'backend', d.get('backend'))"

echo "==> GET $API/api/v1/folding/savings"
sv="$(curl -sfS "${HDR[@]}" "$API/api/v1/folding/savings")" || fail "folding savings"
echo "$sv" | python3 -c "import json,sys; d=json.load(sys.stdin); print('saved', d.get('totals',{}).get('saved_human'), 'ops', d.get('totals',{}).get('operations'))"

for lane in cpu memory network storage; do
  echo "==> POST /api/v1/folding/filter/$lane"
  resp="$(curl -sfS "${HDR[@]}" -X POST -H 'Content-Type: application/json' \
    -d "{\"payload\":\"{\\\"lane\\\":\\\"$lane\\\",\\\"probe\\\":true}\"}" \
    "$API/api/v1/folding/filter/$lane")" || fail "lane $lane"
  echo "$resp" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('orig_size'); print(sys.argv[1], 'ratio', d.get('ratio'))" "$lane"
done

echo "==> POST /api/v1/folding/wire/compress"
PAYLOAD_B64="$(python3 -c 'import base64; print(base64.b64encode(b"x"*4096).decode())')"
wire="$(curl -sfS "${HDR[@]}" -X POST -H 'Content-Type: application/json' \
  -d "{\"payload_b64\":\"$PAYLOAD_B64\"}" \
  "$API/api/v1/folding/wire/compress")" || fail "wire compress"
echo "$wire" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d.get('compressed_size'); print('wire ratio', d.get('ratio'))"

pass "verify-array-firewall-folding complete"
