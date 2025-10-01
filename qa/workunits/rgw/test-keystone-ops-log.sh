#!/usr/bin/env bash
#
# Test for Keystone application credentials in RGW ops log
#
# This test verifies that when RGW is configured with rgw_ops_log_keystone_scope=true,
# Keystone identity data (including application credentials) appears in the ops log.
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source $SCRIPT_DIR/../standalone/ceph-helpers.sh

# Test configuration
OPS_LOG_FILE="/tmp/rgw-ops-test-$$.log"
RGW_PORT=17480
KEYSTONE_PORT=35357

# Cleanup on exit
trap cleanup EXIT
function cleanup() {
    if [[ -n "$KEYSTONE_PID" ]]; then
        kill $KEYSTONE_PID 2>/dev/null || true
    fi
    rm -f $OPS_LOG_FILE
}

function start_fake_keystone() {
    echo "Starting fake Keystone server on port $KEYSTONE_PORT..."
    python3 $SCRIPT_DIR/keystone-fake-server.py --port $KEYSTONE_PORT &
    KEYSTONE_PID=$!

    # Wait for server to start
    for i in {1..10}; do
        if curl -s http://localhost:$KEYSTONE_PORT/v3 >/dev/null 2>&1; then
            echo "Fake Keystone server started (PID: $KEYSTONE_PID)"
            return 0
        fi
        sleep 1
    done

    echo "ERROR: Failed to start fake Keystone server"
    return 1
}

function configure_rgw_for_keystone() {
    echo "Configuring RGW for Keystone ops logging..."

    # Set RGW configuration for Keystone
    ceph config set client.rgw rgw_keystone_url http://localhost:$KEYSTONE_PORT
    ceph config set client.rgw rgw_keystone_api_version 3
    ceph config set client.rgw rgw_keystone_accepted_roles admin,Member
    ceph config set client.rgw rgw_keystone_accepted_admin_roles admin
    ceph config set client.rgw rgw_keystone_admin_user admin
    ceph config set client.rgw rgw_keystone_admin_password ADMIN
    ceph config set client.rgw rgw_keystone_admin_project admin
    ceph config set client.rgw rgw_keystone_admin_domain Default
    ceph config set client.rgw rgw_keystone_implicit_tenants true
    ceph config set client.rgw rgw_swift_account_in_url true

    # Enable ops logging with Keystone scope
    ceph config set client.rgw rgw_enable_ops_log true
    ceph config set client.rgw rgw_ops_log_rados false
    ceph config set client.rgw rgw_ops_log_file_path $OPS_LOG_FILE
    ceph config set client.rgw rgw_ops_log_keystone_scope true

    # Restart RGW to apply configuration
    echo "Restarting RGW..."
    systemctl restart ceph-radosgw@rgw.$(hostname -s) || true
    sleep 5
}

function get_keystone_token() {
    # Get a token from fake Keystone with application credential
    local token_response=$(curl -s -X POST http://localhost:$KEYSTONE_PORT/v3/auth/tokens \
        -H "Content-Type: application/json" \
        -d '{
            "auth": {
                "identity": {
                    "methods": ["application_credential"],
                    "application_credential": {
                        "id": "app-cred-test-12345",
                        "secret": "test-secret"
                    }
                },
                "scope": {
                    "project": {
                        "id": "test-project-id",
                        "name": "test-project",
                        "domain": {
                            "id": "default",
                            "name": "Default"
                        }
                    }
                }
            }
        }' -i 2>/dev/null | grep -i x-subject-token | awk '{print $2}' | tr -d '\r')

    echo "$token_response"
}

function test_keystone_ops_logging() {
    echo "Testing Keystone ops logging..."

    # Clear ops log
    > $OPS_LOG_FILE

    # Get Keystone token with application credential
    local token=$(get_keystone_token)
    if [[ -z "$token" ]]; then
        echo "ERROR: Failed to get Keystone token"
        return 1
    fi
    echo "Got Keystone token: ${token:0:20}..."

    # Make request to RGW with Keystone token
    echo "Making request to RGW with Keystone token..."
    curl -s -H "X-Auth-Token: $token" \
         http://localhost:$RGW_PORT/ || true

    # Wait for log to be written
    sleep 2

    # Check if ops log contains keystone_scope
    echo "Checking ops log for keystone_scope..."
    if [[ ! -f $OPS_LOG_FILE ]]; then
        echo "ERROR: Ops log file not found: $OPS_LOG_FILE"
        return 1
    fi

    local last_entry=$(tail -1 $OPS_LOG_FILE)
    if [[ -z "$last_entry" ]]; then
        echo "ERROR: No entries in ops log"
        return 1
    fi

    # Parse JSON and check for keystone_scope
    if echo "$last_entry" | python3 -c "
import sys, json
entry = json.load(sys.stdin)
if 'keystone_scope' not in entry:
    print('ERROR: No keystone_scope in ops log entry')
    sys.exit(1)

ks = entry['keystone_scope']
print('Found keystone_scope in ops log')

# Check for application_credential
if 'application_credential' in ks:
    app_cred = ks['application_credential']
    if 'id' in app_cred:
        print(f'  Application credential ID: {app_cred[\"id\"]}')
        if app_cred['id'] == 'app-cred-test-12345':
            print('SUCCESS: Application credential correctly logged!')
            sys.exit(0)
        else:
            print(f'ERROR: Wrong app credential ID: {app_cred[\"id\"]}')
            sys.exit(1)

print('ERROR: No application_credential in keystone_scope')
sys.exit(1)
"; then
        echo "TEST PASSED: Keystone application credential logging works!"
        return 0
    else
        echo "TEST FAILED: Application credential not properly logged"
        return 1
    fi
}

function test_non_keystone_auth() {
    echo "Testing non-Keystone authentication (should not have keystone_scope)..."

    # Clear ops log
    > $OPS_LOG_FILE

    # Make request without Keystone token
    curl -s http://localhost:$RGW_PORT/ || true

    # Wait for log to be written
    sleep 2

    # Check that ops log does NOT contain keystone_scope
    if [[ -f $OPS_LOG_FILE ]]; then
        local last_entry=$(tail -1 $OPS_LOG_FILE)
        if [[ -n "$last_entry" ]]; then
            if echo "$last_entry" | grep -q "keystone_scope"; then
                echo "ERROR: keystone_scope found when using non-Keystone auth"
                return 1
            else
                echo "SUCCESS: No keystone_scope for non-Keystone auth"
                return 0
            fi
        fi
    fi
    return 0
}

# Main test execution
function main() {
    echo "=== RGW Keystone Ops Log Integration Test ==="
    echo ""

    # Start fake Keystone server
    if ! start_fake_keystone; then
        echo "Failed to start fake Keystone server"
        exit 1
    fi

    # Configure RGW for Keystone
    configure_rgw_for_keystone

    # Run tests
    local test_passed=true

    echo ""
    echo "=== Test 1: Keystone Authentication with Application Credentials ==="
    if test_keystone_ops_logging; then
        echo "PASS"
    else
        echo "FAIL"
        test_passed=false
    fi

    echo ""
    echo "=== Test 2: Non-Keystone Authentication ==="
    if test_non_keystone_auth; then
        echo "PASS"
    else
        echo "FAIL"
        test_passed=false
    fi

    echo ""
    echo "=== Test Summary ==="
    if $test_passed; then
        echo "ALL TESTS PASSED"
        exit 0
    else
        echo "SOME TESTS FAILED"
        exit 1
    fi
}

# Run the test
main "$@"