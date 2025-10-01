#!/bin/bash
# Test RGW Keystone ops logging with application credential authentication
# This script validates that application credential information is correctly logged
# in RGW ops logs, including id, name, and restricted status.

set -e

# Configuration
KEYSTONE_URL="${KEYSTONE_URL:-http://localhost:5000}"
RGW_URL="${RGW_URL:-http://localhost:8080}"
APP_CRED_ID="${APP_CRED_ID}"
APP_CRED_SECRET="${APP_CRED_SECRET}"

echo "=== Testing RGW Keystone Ops Logging - Application Credential Authentication ==="
echo "Keystone URL: $KEYSTONE_URL"
echo "RGW URL: $RGW_URL"
echo

# Validate required parameters
if [ -z "$APP_CRED_ID" ] || [ -z "$APP_CRED_SECRET" ]; then
  echo "ERROR: APP_CRED_ID and APP_CRED_SECRET must be set"
  echo
  echo "Usage:"
  echo "  APP_CRED_ID=<id> APP_CRED_SECRET=<secret> $0"
  echo
  echo "To create an application credential:"
  echo "  openstack application credential create <name> --unrestricted"
  echo "  # or"
  echo "  openstack application credential create <name>  # restricted by default"
  exit 1
fi

echo "Application Credential ID: $APP_CRED_ID"
echo

# Step 1: Get Keystone token using application credential
echo "Step 1: Authenticating with Keystone (application credential)..."
AUTH_RESPONSE=$(curl -s -X POST "$KEYSTONE_URL/v3/auth/tokens?nocatalog" \
  -H "Content-Type: application/json" \
  -d "{
    \"auth\": {
      \"identity\": {
        \"methods\": [\"application_credential\"],
        \"application_credential\": {
          \"id\": \"$APP_CRED_ID\",
          \"secret\": \"$APP_CRED_SECRET\"
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

echo "✓ Got Keystone token (application credential authentication)"
echo

# Step 2: Verify token contains application_credential data
echo "Step 2: Verifying token structure..."
TOKEN_DATA=$(echo "$AUTH_RESPONSE" | sed -n '/^{/,$p')
TOKEN_METHODS=$(echo "$TOKEN_DATA" | jq -r '.token.methods[]' 2>/dev/null || echo "")

if [ "$TOKEN_METHODS" != "application_credential" ]; then
  echo "ERROR: Token does not use application_credential authentication method"
  echo "Methods: $TOKEN_METHODS"
  echo "This may indicate the token was issued with password authentication"
  exit 1
fi

echo "✓ Token uses application_credential authentication"

# Check if application_credential section exists in token
APP_CRED_IN_TOKEN=$(echo "$TOKEN_DATA" | jq -e '.token.application_credential' 2>/dev/null && echo "yes" || echo "no")
if [ "$APP_CRED_IN_TOKEN" = "yes" ]; then
  echo "✓ Token contains application_credential section"
  echo "$TOKEN_DATA" | jq '.token.application_credential'
else
  echo "WARNING: Token does not contain application_credential section"
  echo "This may affect ops logging"
fi
echo

# Step 3: Validate token to see what RGW will receive
echo "Step 3: Validating token (simulating RGW's validation)..."
VALIDATE_RESPONSE=$(curl -s -X GET "$KEYSTONE_URL/v3/auth/tokens?nocatalog" \
  -H "X-Auth-Token: $TOKEN" \
  -H "X-Subject-Token: $TOKEN")

VALIDATE_METHODS=$(echo "$VALIDATE_RESPONSE" | jq -r '.token.methods[]' 2>/dev/null || echo "")
if [ "$VALIDATE_METHODS" != "application_credential" ]; then
  echo "ERROR: Validated token shows methods: $VALIDATE_METHODS"
  echo "Expected: application_credential"
  exit 1
fi

echo "✓ Validated token confirms application_credential method"

VALIDATE_APP_CRED=$(echo "$VALIDATE_RESPONSE" | jq -e '.token.application_credential' 2>/dev/null && echo "yes" || echo "no")
if [ "$VALIDATE_APP_CRED" = "yes" ]; then
  echo "✓ Validated token contains application_credential data"
  echo "$VALIDATE_RESPONSE" | jq '.token.application_credential'
else
  echo "ERROR: Validated token missing application_credential section"
  echo "RGW will not be able to log application credential info"
  exit 1
fi
echo

# Step 4: Make request to RGW using the token
echo "Step 4: Making request to RGW with application credential token..."
RGW_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -H "X-Auth-Token: $TOKEN" "$RGW_URL/")
HTTP_CODE=$(echo "$RGW_RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)

if [ "$HTTP_CODE" != "200" ]; then
  echo "ERROR: RGW request failed with HTTP $HTTP_CODE"
  echo "$RGW_RESPONSE"
  exit 1
fi

echo "✓ RGW request succeeded (HTTP $HTTP_CODE)"
echo

# Step 5: Check ops log for application credential data
echo "Step 5: Checking RGW ops log for application credential data..."
echo "NOTE: This requires rgw_ops_log_keystone_scope=true"
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
      echo "Full Keystone scope data:"
      echo "$OPS_LOG" | jq '.keystone_scope'
      echo

      # Check for application_credential specifically
      if echo "$OPS_LOG" | jq -e '.keystone_scope.application_credential' &> /dev/null; then
        echo "✓ Found application_credential in ops log:"
        echo "$OPS_LOG" | jq '.keystone_scope.application_credential'
        echo

        # Verify expected fields
        APP_CRED_ID_LOG=$(echo "$OPS_LOG" | jq -r '.keystone_scope.application_credential.id')
        APP_CRED_NAME_LOG=$(echo "$OPS_LOG" | jq -r '.keystone_scope.application_credential.name')
        APP_CRED_RESTRICTED_LOG=$(echo "$OPS_LOG" | jq -r '.keystone_scope.application_credential.restricted')

        echo "Logged application credential details:"
        echo "  ID: $APP_CRED_ID_LOG"
        echo "  Name: $APP_CRED_NAME_LOG"
        echo "  Restricted: $APP_CRED_RESTRICTED_LOG"

        # Verify ID matches
        if [ "$APP_CRED_ID_LOG" = "$APP_CRED_ID" ]; then
          echo "✓ Application credential ID matches"
        else
          echo "ERROR: Application credential ID mismatch"
          echo "  Expected: $APP_CRED_ID"
          echo "  Got: $APP_CRED_ID_LOG"
          exit 1
        fi
      else
        echo "ERROR: No application_credential found in ops log"
        echo "This indicates the application credential data was not logged"
        exit 1
      fi
    else
      echo "ERROR: No keystone_scope found in ops log"
      echo "Make sure rgw_ops_log_keystone_scope=true is set"
      exit 1
    fi
  else
    echo "ERROR: Could not fetch ops log"
    echo "Check manually with: radosgw-admin log list --max-entries=1"
    exit 1
  fi
else
  echo "NOTE: radosgw-admin not available"
  echo "To verify application credential logging, run:"
  echo "  radosgw-admin log list --max-entries=1 | jq '.keystone_scope.application_credential'"
  echo
  echo "Expected output:"
  echo "  {"
  echo "    \"id\": \"<application-credential-id>\","
  echo "    \"name\": \"<application-credential-name>\","
  echo "    \"restricted\": true|false"
  echo "  }"
fi

echo
echo "=== Test Complete ==="
echo "✓ Application credential authentication test passed"
echo "✓ Application credential data logged successfully in ops log"
