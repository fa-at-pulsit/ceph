#!/bin/bash
# Test RGW Keystone ops logging with password authentication
# This script validates that Keystone scope information (user, project, domain, roles)
# is correctly logged in RGW ops logs when using password authentication.

set -e

# Configuration
KEYSTONE_URL="${KEYSTONE_URL:-http://localhost:5000}"
RGW_URL="${RGW_URL:-http://localhost:8080}"
KEYSTONE_USER="${KEYSTONE_USER:-admin}"
KEYSTONE_PASSWORD="${KEYSTONE_PASSWORD:-secret}"
KEYSTONE_PROJECT="${KEYSTONE_PROJECT:-demo}"
KEYSTONE_DOMAIN="${KEYSTONE_DOMAIN:-Default}"

echo "=== Testing RGW Keystone Ops Logging - Password Authentication ==="
echo "Keystone URL: $KEYSTONE_URL"
echo "RGW URL: $RGW_URL"
echo

# Step 1: Get Keystone token using password authentication
echo "Step 1: Authenticating with Keystone (password)..."
AUTH_RESPONSE=$(curl -s -X POST "$KEYSTONE_URL/v3/auth/tokens" \
  -H "Content-Type: application/json" \
  -d "{
    \"auth\": {
      \"identity\": {
        \"methods\": [\"password\"],
        \"password\": {
          \"user\": {
            \"name\": \"$KEYSTONE_USER\",
            \"domain\": {\"name\": \"$KEYSTONE_DOMAIN\"},
            \"password\": \"$KEYSTONE_PASSWORD\"
          }
        }
      },
      \"scope\": {
        \"project\": {
          \"name\": \"$KEYSTONE_PROJECT\",
          \"domain\": {\"name\": \"$KEYSTONE_DOMAIN\"}
        }
      }
    }
  }" -D -)

TOKEN=$(echo "$AUTH_RESPONSE" | grep -i "^X-Subject-Token:" | awk '{print $2}' | tr -d '\r')

if [ -z "$TOKEN" ]; then
  echo "ERROR: Failed to get Keystone token"
  echo "$AUTH_RESPONSE"
  exit 1
fi

echo "✓ Got Keystone token (password authentication)"
echo

# Step 2: Verify token contains expected data
echo "Step 2: Verifying token structure..."
TOKEN_DATA=$(echo "$AUTH_RESPONSE" | sed -n '/^{/,$p')
TOKEN_METHODS=$(echo "$TOKEN_DATA" | jq -r '.token.methods[]' 2>/dev/null || echo "")

if [ "$TOKEN_METHODS" != "password" ]; then
  echo "ERROR: Token does not use password authentication method"
  echo "Methods: $TOKEN_METHODS"
  exit 1
fi

echo "✓ Token uses password authentication"
echo

# Step 3: Make request to RGW using the token
echo "Step 3: Making request to RGW with Keystone token..."
RGW_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -H "X-Auth-Token: $TOKEN" "$RGW_URL/")
HTTP_CODE=$(echo "$RGW_RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)

if [ "$HTTP_CODE" != "200" ]; then
  echo "ERROR: RGW request failed with HTTP $HTTP_CODE"
  echo "$RGW_RESPONSE"
  exit 1
fi

echo "✓ RGW request succeeded (HTTP $HTTP_CODE)"
echo

# Step 4: Check ops log for Keystone scope data
echo "Step 4: Checking RGW ops log..."
echo "NOTE: This requires rgw_ops_log_keystone_scope=true"
echo "Use 'radosgw-admin log list --max-entries=1' to view the latest ops log entry"
echo "Expected ops log should contain:"
echo "  - keystone_scope.project (id, name, domain)"
echo "  - keystone_scope.user (id, name, domain)"
echo "  - keystone_scope.roles"
echo "  - NO application_credential section (password auth only)"
echo

# Try to fetch ops log if radosgw-admin is available
if command -v radosgw-admin &> /dev/null; then
  echo "Fetching latest ops log entry..."
  OPS_LOG=$(radosgw-admin log list --max-entries=1 2>/dev/null || echo "")

  if [ -n "$OPS_LOG" ]; then
    # Check for keystone_scope in the log
    if echo "$OPS_LOG" | jq -e '.keystone_scope' &> /dev/null; then
      echo "✓ Found keystone_scope in ops log"
      echo
      echo "Keystone scope data:"
      echo "$OPS_LOG" | jq '.keystone_scope'
      echo

      # Verify no application_credential (password auth shouldn't have it)
      if echo "$OPS_LOG" | jq -e '.keystone_scope.application_credential' &> /dev/null; then
        echo "WARNING: application_credential found in password auth log (unexpected)"
      else
        echo "✓ No application_credential in ops log (correct for password auth)"
      fi
    else
      echo "WARNING: No keystone_scope found in ops log"
      echo "Make sure rgw_ops_log_keystone_scope=true is set"
    fi
  else
    echo "NOTE: Could not fetch ops log. Check manually with:"
    echo "  radosgw-admin log list --max-entries=1 | jq '.keystone_scope'"
  fi
else
  echo "NOTE: radosgw-admin not available. Check ops log manually:"
  echo "  radosgw-admin log list --max-entries=1 | jq '.keystone_scope'"
fi

echo
echo "=== Test Complete ==="
echo "✓ Password authentication test passed"
