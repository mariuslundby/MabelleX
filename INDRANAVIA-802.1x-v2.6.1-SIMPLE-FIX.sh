#!/bin/bash

# Force execution with bash if not already running in bash
if [ -z "$BASH_VERSION" ]; then
    exec /bin/bash "$0" "$@"
fi

set -o pipefail

SCRIPT_VERSION="2.6.1"
TEST_MODE=false

if [[ "$1" == "--test" ]]; then
    TEST_MODE=true
    echo "=== TEST MODE ENABLED ==="
    echo "No changes will be made to the system"
    echo ""
fi

SCEP_URL="https://ndesscep-indranavia.msappproxy.net/certsrv/mscep/mscep.dll"
CA_NAME="NDES"
DOMAIN_SUFFIX="ad.indra.no"

CERT_BASE_PATH="/etc/pki/802.1x"
MACHINE_CERT="${CERT_BASE_PATH}/machine.crt"
MACHINE_KEY="${CERT_BASE_PATH}/machine.key"
CA_CERT="${CERT_BASE_PATH}/ca-chain.pem"
SCEP_SERVER_CA_CERT="${CERT_BASE_PATH}/scep-server-ca.pem"

WIRED_CONNECTION_NAME="Wired-802.1x"
WIRED_PRIORITY=100

WIFI_CONNECTION_NAME="IndraNavia"
WIFI_SSID="IndraNavia"
WIFI_PRIORITY=50

EAP_METHOD="tls"

EXISTING_FALLBACK_PRIORITY=5
OLD_INDRA_PRIORITY=1

LOG_FILE="/var/log/enterprise-network-deployment.log"
STATE_FILE="/tmp/enterprise-deployment-state.$$"
ROLLBACK_LOG="/var/log/enterprise-network-rollback.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    if [ "$TEST_MODE" = true ]; then
        echo "[TEST] $1"
    fi
    echo "[LOG] $1"
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"
    if [ "$TEST_MODE" = true ]; then
        echo "[TEST ERROR] $1"
    fi
}

log_section() {
    echo "" >> "$LOG_FILE"
    echo "==========================================" >> "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
    echo "==========================================" >> "$LOG_FILE"
    if [ "$TEST_MODE" = true ]; then
        echo ""
        echo "=== $1 ==="
    fi
}

log_warn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: $1" >> "$LOG_FILE"
    if [ "$TEST_MODE" = true ]; then
        echo "[TEST WARN] $1"
    fi
}

log_success() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓ $1" >> "$LOG_FILE"
    if [ "$TEST_MODE" = true ]; then
        echo "[TEST ✓] $1"
    fi
}

log_debug() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] DEBUG: $1" >> "$LOG_FILE"
}

record_state() {
    echo "$1" >> "$STATE_FILE"
    log_debug "Rollback point: $1"
}

rollback() {
    if [ ! -f "$STATE_FILE" ]; then
        return
    fi

    log_error "Deployment failed - initiating rollback..."
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] === ROLLBACK STARTED ===" >> "$ROLLBACK_LOG"

    local ROLLBACK_SUCCESS=true

    while IFS= read -r action; do
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Processing: $action" >> "$ROLLBACK_LOG"

        case "$action" in
            CERT_REQUESTED:*)
                REQ_ID="${action#CERT_REQUESTED:}"
                log "Rolling back certificate request: $REQ_ID"
                if getcert stop-tracking -i "$REQ_ID" 2>/dev/null; then
                    echo "  ✓ Removed certificate tracking: $REQ_ID" >> "$ROLLBACK_LOG"
                else
                    echo "  ✗ Failed to remove certificate tracking: $REQ_ID" >> "$ROLLBACK_LOG"
                    ROLLBACK_SUCCESS=false
                fi
                ;;
            CONNECTION_CREATED:*)
                CONN_NAME="${action#CONNECTION_CREATED:}"
                log "Rolling back connection: $CONN_NAME"
                if nmcli connection delete "$CONN_NAME" 2>/dev/null; then
                    echo "  ✓ Deleted connection: $CONN_NAME" >> "$ROLLBACK_LOG"
                else
                    echo "  ✗ Failed to delete connection: $CONN_NAME" >> "$ROLLBACK_LOG"
                    ROLLBACK_SUCCESS=false
                fi
                ;;
            FILE_MODIFIED:*)
                FILE_PATH="${action#FILE_MODIFIED:}"
                if [ -f "${FILE_PATH}.backup-rollback" ]; then
                    log "Restoring file: $FILE_PATH"
                    if mv "${FILE_PATH}.backup-rollback" "$FILE_PATH"; then
                        echo "  ✓ Restored file: $FILE_PATH" >> "$ROLLBACK_LOG"
                    else
                        echo "  ✗ Failed to restore file: $FILE_PATH" >> "$ROLLBACK_LOG"
                        ROLLBACK_SUCCESS=false
                    fi
                fi
                ;;
            CA_ADDED:*)
                CA_TO_REMOVE="${action#CA_ADDED:}"
                log "Rolling back CA: $CA_TO_REMOVE"
                if getcert remove-ca -c "$CA_TO_REMOVE" 2>/dev/null; then
                    echo "  ✓ Removed CA: $CA_TO_REMOVE" >> "$ROLLBACK_LOG"
                else
                    echo "  ✗ Failed to remove CA: $CA_TO_REMOVE" >> "$ROLLBACK_LOG"
                    ROLLBACK_SUCCESS=false
                fi
                ;;
        esac
    done < "$STATE_FILE"

    rm -f "$STATE_FILE"

    if [ "$ROLLBACK_SUCCESS" = true ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] === ROLLBACK COMPLETED SUCCESSFULLY ===" >> "$ROLLBACK_LOG"
        log_error "Rollback complete. Check logs: $LOG_FILE and $ROLLBACK_LOG"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] === ROLLBACK COMPLETED WITH ERRORS ===" >> "$ROLLBACK_LOG"
        log_error "Rollback completed with errors. Manual cleanup may be required. Check: $ROLLBACK_LOG"
    fi
}

safe_execute() {
    local description="$1"
    local command="$2"
    local critical="${3:-true}"

    log_debug "Executing: $description"

    if [ "$TEST_MODE" = true ]; then
        log "[TEST] Would execute: $description"
        return 0
    fi

    if eval "$command" >> "$LOG_FILE" 2>&1; then
        log_success "$description"
        return 0
    else
        local exit_code=$?
        log_error "$description failed (exit code: $exit_code)"

        if [ "$critical" = true ]; then
            log_error "Critical failure - aborting"
            return 1
        else
            log_warn "Non-critical failure - continuing"
            return 0
        fi
    fi
}

cleanup_on_exit() {
    EXIT_CODE=$?

    if [ $EXIT_CODE -ne 0 ] && [ "$TEST_MODE" = false ]; then
        log_error "Script exited with code: $EXIT_CODE"
        rollback
        echo "FAILED: Deployment failed on $(hostname). Check log: $LOG_FILE" >&2
    else
        rm -f "$STATE_FILE"
        if [ "$TEST_MODE" = true ]; then
            echo ""
            echo "=== TEST MODE COMPLETED ==="
            echo "No actual changes were made"
            echo "Review test output above"
        fi
    fi
}

trap cleanup_on_exit EXIT

download_scep_server_ca() {
    log "Downloading SCEP server's TLS CA certificate..."

    # Extract hostname from SCEP URL
    SCEP_HOST=$(echo "$SCEP_URL" | sed 's|https://||;s|/.*||')

    # Method 1: Try to get the cert from the TLS connection
    if timeout 10 openssl s_client -connect "${SCEP_HOST}:443" -showcerts </dev/null 2>/dev/null |         openssl x509 -outform PEM > "$SCEP_SERVER_CA_CERT" 2>/dev/null; then

        if [ -s "$SCEP_SERVER_CA_CERT" ]; then
            log_success "Downloaded SCEP server TLS certificate via openssl"
            chmod 644 "$SCEP_SERVER_CA_CERT"
            return 0
        fi
    fi

    # Method 2: Use curl to extract certificate chain
    log_warn "Method 1 failed, trying curl certificate extraction..."
    if timeout 10 curl -vI "https://${SCEP_HOST}" 2>&1 | grep "server certificate" -A 20 > /tmp/cert_info.txt; then
        log_debug "Got certificate info from curl"
    fi

    # Method 3: Try using system CA bundle (might already trust it)
    if [ -f /etc/ssl/certs/ca-certificates.crt ]; then
        log "Using system CA bundle as fallback"
        cp /etc/ssl/certs/ca-certificates.crt "$SCEP_SERVER_CA_CERT"
        chmod 644 "$SCEP_SERVER_CA_CERT"
        return 0
    elif [ -f /etc/pki/tls/certs/ca-bundle.crt ]; then
        log "Using system CA bundle as fallback (RHEL)"
        cp /etc/pki/tls/certs/ca-bundle.crt "$SCEP_SERVER_CA_CERT"
        chmod 644 "$SCEP_SERVER_CA_CERT"
        return 0
    fi

    log_error "Failed to download SCEP server CA certificate"
    return 1
}

configure_scep_ca() {
    log "Configuring SCEP CA: $CA_NAME"

    # Remove existing CA
    if getcert list-cas 2>/dev/null | grep -q "^CA '$CA_NAME'"; then
        log "Removing existing CA..."
        getcert remove-ca -c "$CA_NAME" 2>/dev/null || true
        sleep 3
    fi

    # Detect SCEP helper
    local SCEP_HELPER=""
    if [ -f /usr/libexec/certmonger/scep-submit ]; then
        SCEP_HELPER="/usr/libexec/certmonger/scep-submit"
    elif [ -f /usr/lib/certmonger/scep-submit ]; then
        SCEP_HELPER="/usr/lib/certmonger/scep-submit"
    else
        log_error "SCEP helper not found"
        return 1
    fi

    SCEP_HOST=$(echo "$SCEP_URL" | sed 's|https://||;s|http://||;s|/.*||')
    log "SCEP server: $SCEP_HOST"

    # Download CA bundle
    echo "=== DOWNLOADING CA BUNDLE ==="
    log "Downloading CA certificates..."

    rm -f /tmp/ndes-ca.crt 2>/dev/null

    if timeout 30 $SCEP_HELPER -u "$SCEP_URL" -C /tmp/ndes-ca.crt 2>&1 | head -20; then
        if [ -s /tmp/ndes-ca.crt ]; then
            log_success "Downloaded CA bundle: $(wc -c < /tmp/ndes-ca.crt) bytes"
        else
            log_warn "scep-submit produced empty file"
        fi
    else
        log_warn "scep-submit failed"
    fi

    # Fallback: GetCACert
    if [ ! -s /tmp/ndes-ca.crt ]; then
        log "Trying GetCACert operation..."
        GETCACERT_URL="${SCEP_URL}?operation=GetCACert&message=CA"

        if timeout 30 curl -k -s "$GETCACERT_URL" -o /tmp/ndes-ca.p7b 2>&1 && [ -s /tmp/ndes-ca.p7b ]; then
            openssl pkcs7 -in /tmp/ndes-ca.p7b -inform DER -print_certs -out /tmp/ndes-ca.crt 2>&1
            if [ -s /tmp/ndes-ca.crt ]; then
                log_success "Downloaded via GetCACert: $(wc -c < /tmp/ndes-ca.crt) bytes"
            fi
        fi
    fi

    if [ ! -s /tmp/ndes-ca.crt ]; then
        log_error "Failed to download CA certificate"
        return 1
    fi

    # Install in system trust
    echo "=== INSTALLING IN TRUST STORE ==="
    if [ -d /etc/pki/ca-trust/source/anchors ]; then
        cp /tmp/ndes-ca.crt /etc/pki/ca-trust/source/anchors/ndes-ca.crt
        update-ca-trust extract 2>&1 | head -3
        log_success "Installed in trust store (RHEL/Fedora/Rocky/CentOS)"
    elif [ -d /usr/local/share/ca-certificates ]; then
        cp /tmp/ndes-ca.crt /usr/local/share/ca-certificates/ndes-ca.crt
        update-ca-certificates 2>&1 | head -3
        log_success "Installed in trust store (Debian/Ubuntu)"
    fi
    sleep 5

    # Add SCEP CA - try different methods
    echo "=== ADDING SCEP CA ==="

    # Method 1: With -R and -r (both point to same bundle)
    log "Method 1: With -R and -r flags (RA+CA bundle)..."
    SCEP_OUTPUT=$(getcert add-scep-ca -c "$CA_NAME" -u "$SCEP_URL" -R /tmp/ndes-ca.crt -r /tmp/ndes-ca.crt 2>&1)
    echo "$SCEP_OUTPUT"

    sleep 10

    if getcert list-cas 2>/dev/null | grep -q "^CA '$CA_NAME'"; then
        log_success "CA added with method 1"
        getcert list-cas -c "$CA_NAME" 2>&1
        record_state "CA_ADDED:$CA_NAME"
        sleep 10
        return 0
    fi

    # Method 2: Only -R flag
    log_warn "Method 1 failed, trying method 2: Only -R flag..."
    getcert remove-ca -c "$CA_NAME" 2>/dev/null || true
    sleep 3

    SCEP_OUTPUT=$(getcert add-scep-ca -c "$CA_NAME" -u "$SCEP_URL" -R /tmp/ndes-ca.crt 2>&1)
    echo "$SCEP_OUTPUT"

    sleep 10

    if getcert list-cas 2>/dev/null | grep -q "^CA '$CA_NAME'"; then
        log_success "CA added with method 2"
        getcert list-cas -c "$CA_NAME" 2>&1
        record_state "CA_ADDED:$CA_NAME"
        sleep 10
        return 0
    fi

    # Method 3: No flags, rely on system trust
    log_warn "Method 2 failed, trying method 3: System trust only..."
    getcert remove-ca -c "$CA_NAME" 2>/dev/null || true
    sleep 3

    SCEP_OUTPUT=$(getcert add-scep-ca -c "$CA_NAME" -u "$SCEP_URL" 2>&1)
    echo "$SCEP_OUTPUT"

    sleep 10

    if getcert list-cas 2>/dev/null | grep -q "^CA '$CA_NAME'"; then
        log_success "CA added with method 3"
        getcert list-cas -c "$CA_NAME" 2>&1
        record_state "CA_ADDED:$CA_NAME"
        sleep 10
        return 0
    fi

    log_error "All CA add methods failed"
    getcert list-cas 2>&1
    return 1
}

preflight_checks() {
    log_section "Pre-flight Checks"

    local CHECKS_PASSED=true

    log "Testing SCEP URL connectivity..."
    if [ "$TEST_MODE" = true ]; then
        log "[TEST] Would test: $SCEP_URL"
    else
        if timeout 15 curl -k -I --connect-timeout 10 "$SCEP_URL" &>/dev/null; then
            log_success "SCEP URL reachable: $SCEP_URL"
        else
            log_error "Cannot reach SCEP URL: $SCEP_URL"
            CHECKS_PASSED=false
        fi
    fi

    log "Checking disk space..."
    AVAILABLE_KB=$(df /etc 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
    if [ "$AVAILABLE_KB" -gt 10240 ]; then
        log_success "Sufficient disk space: ${AVAILABLE_KB}KB available"
    else
        log_error "Insufficient disk space: ${AVAILABLE_KB}KB (need 10MB+)"
        CHECKS_PASSED=false
    fi

    log "Testing DNS resolution..."
    NDES_HOST=$(echo "$SCEP_URL" | sed 's|https://||;s|/.*||')
    if [ "$TEST_MODE" = true ]; then
        log "[TEST] Would test DNS for: $NDES_HOST"
    else
        if timeout 5 host "$NDES_HOST" &>/dev/null; then
            log_success "DNS resolution works for: $NDES_HOST"
        else
            log_warn "DNS resolution failed for: $NDES_HOST (may be expected)"
        fi
    fi

    if [ "$EUID" -eq 0 ]; then
        log_success "Running as root"
    else
        log_error "Must run as root"
        CHECKS_PASSED=false
    fi

    if command -v nmcli &>/dev/null; then
        log_success "NetworkManager available"
    else
        log "NetworkManager not installed (will be installed)"
    fi

    log ""
    if [ "$CHECKS_PASSED" = false ] && [ "$TEST_MODE" = false ]; then
        log_error "Pre-flight checks FAILED"
        exit 1
    else
        log_success "All pre-flight checks PASSED"
    fi
}

verify_deployment() {
    log_section "Post-Deployment Verification"

    local VERIFY_PASSED=true

    if [ "$TEST_MODE" = true ]; then
        log "[TEST] Would verify certificate at: $MACHINE_CERT"
        log "[TEST] Would verify certmonger tracking"
        log "[TEST] Would verify NetworkManager connections"
        log_success "Test mode verification complete"
        return 0
    fi

    log "Verifying certificate..."
    if [ -f "$MACHINE_CERT" ] && [ -f "$MACHINE_KEY" ]; then
        if timeout 5 openssl x509 -in "$MACHINE_CERT" -noout -checkend 86400 &>/dev/null; then
            log_success "Certificate valid and not expiring within 24h"
        else
            log_error "Certificate invalid or expiring soon"
            VERIFY_PASSED=false
        fi
    else
        log_error "Certificate files missing"
        VERIFY_PASSED=false
    fi

    log "Verifying certmonger tracking..."
    REQUEST_ID="enterprise-8021x-${HOSTNAME}"
    if getcert list -i "$REQUEST_ID" 2>/dev/null | grep -q "status: MONITORING"; then
        log_success "Certmonger tracking active: $REQUEST_ID"
    else
        log_error "Certmonger not tracking certificate"
        VERIFY_PASSED=false
    fi

    log "Verifying NetworkManager connections..."
    if nmcli connection show "$WIRED_CONNECTION_NAME" &>/dev/null 2>&1; then
        log_success "Wired 802.1x connection exists"
    else
        log_warn "Wired 802.1x connection not created"
    fi

    log "Testing network connectivity..."
    if timeout 3 ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
        log_success "Network connectivity OK"
    else
        log_warn "No network connectivity (may be expected if offline)"
    fi

    log ""
    if [ "$VERIFY_PASSED" = false ]; then
        log_error "Deployment verification FAILED"
        return 1
    else
        log_success "All deployment verifications PASSED"
        return 0
    fi
}

log_section "Enterprise Network Deployment Starting"
log "Version: $SCRIPT_VERSION"
log "Test Mode: $TEST_MODE"

if [ "$TEST_MODE" = false ]; then
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
fi

preflight_checks

HOSTNAME=$(hostname -s)
FQDN="${HOSTNAME}.${DOMAIN_SUFFIX}"
log "Hostname: $HOSTNAME"
log "FQDN: $FQDN"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    log "OS: $NAME $VERSION_ID"
else
    log_error "Cannot detect OS"
    exit 1
fi

if ! command -v nmcli &>/dev/null; then
    log "NetworkManager not found - installing..."

    if [ "$TEST_MODE" = true ]; then
        log "[TEST] Would install NetworkManager for OS: $OS"
    else
        case "$OS" in
            fedora|rhel|centos|rocky|almalinux)
                safe_execute "Installing NetworkManager on RHEL/Fedora"                     "dnf install -y NetworkManager NetworkManager-wifi"
                ;;
            debian|ubuntu)
                export DEBIAN_FRONTEND=noninteractive
                safe_execute "Installing NetworkManager on Debian/Ubuntu"                     "apt-get update -qq && apt-get install -y network-manager"
                ;;
            *)
                log_error "Unsupported OS: $OS"
                exit 1
                ;;
        esac
    fi

    log_success "NetworkManager installed"
fi

log "Checking for network management conflicts..."

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Would check and disable systemd-networkd if active"
    log "[TEST] Would configure netplan for NetworkManager if present"
else
    if systemctl is-active --quiet systemd-networkd; then
        log_warn "systemd-networkd is active - disabling"
        systemctl stop systemd-networkd &>/dev/null || true
        systemctl disable systemd-networkd &>/dev/null || true
        log_success "systemd-networkd disabled"
    fi

    if [ -d /etc/netplan ] && [ "$(ls -A /etc/netplan/*.yaml 2>/dev/null)" ]; then
        log_warn "Netplan configuration detected - switching to NetworkManager"

        BACKUP_DIR="/etc/netplan.backup-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        cp /etc/netplan/*.yaml "$BACKUP_DIR/" 2>/dev/null || true
        log "Netplan backed up to: $BACKUP_DIR"

        cat > /etc/netplan/01-network-manager-all.yaml <<'EOF'
network:
  version: 2
  renderer: NetworkManager
EOF

        record_state "FILE_MODIFIED:/etc/netplan/01-network-manager-all.yaml"

        if command -v netplan &>/dev/null; then
            netplan apply &>/dev/null || true
        fi

        log_success "Netplan configured for NetworkManager"
    fi
fi

if [ "$TEST_MODE" = false ]; then
    if ! systemctl is-active --quiet NetworkManager; then
        log "Starting NetworkManager..."

        systemctl enable NetworkManager &>/dev/null
        systemctl start NetworkManager

        TIMEOUT=30
        ELAPSED=0
        while [ $ELAPSED -lt $TIMEOUT ]; do
            if systemctl is-active --quiet NetworkManager; then
                log_success "NetworkManager started"
                sleep 5
                break
            fi
            sleep 1
            ELAPSED=$((ELAPSED + 1))
        done

        if ! systemctl is-active --quiet NetworkManager; then
            log_error "NetworkManager failed to start"
            systemctl status NetworkManager >> "$LOG_FILE" 2>&1
            exit 1
        fi
    else
        log "NetworkManager: already running"
    fi

    if ! command -v nmcli &>/dev/null; then
        log_error "nmcli still not available after installation"
        exit 1
    fi

    if ! nmcli general status &>/dev/null; then
        log_error "nmcli not responding"
        exit 1
    fi

    log_success "NetworkManager ready"
fi

log_section "[1/9] Detecting Current Network Status"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Would detect active wired and WiFi connections"
    ACTIVE_CONNECTIONS=""
    ACTIVE_WIRED_CONNECTION=""
    ACTIVE_WIFI_CONNECTION=""
else
    ACTIVE_CONNECTIONS=$(nmcli -t -f NAME,TYPE,DEVICE connection show --active 2>/dev/null || true)

    if [ -n "$ACTIVE_CONNECTIONS" ]; then
        log "Currently active connections:"
        echo "$ACTIVE_CONNECTIONS" | while IFS=: read -r name type device; do
            log "  - $name ($type on $device)"
        done
    else
        log "No active connections"
    fi

    ACTIVE_WIRED_CONNECTION=""
    ACTIVE_WIFI_CONNECTION=""

    ACTIVE_WIRED=$(echo "$ACTIVE_CONNECTIONS" | grep ":ethernet:" | head -1 || true)
    if [ -n "$ACTIVE_WIRED" ]; then
        ACTIVE_WIRED_CONNECTION=$(echo "$ACTIVE_WIRED" | cut -d: -f1)
        ACTIVE_WIRED_DEVICE=$(echo "$ACTIVE_WIRED" | cut -d: -f3)
        log "Active wired: $ACTIVE_WIRED_CONNECTION on $ACTIVE_WIRED_DEVICE"
    fi

    ACTIVE_WIFI=$(echo "$ACTIVE_CONNECTIONS" | grep ":wifi:" | head -1 || true)
    if [ -n "$ACTIVE_WIFI" ]; then
        ACTIVE_WIFI_CONNECTION=$(echo "$ACTIVE_WIFI" | cut -d: -f1)
        ACTIVE_WIFI_DEVICE=$(echo "$ACTIVE_WIFI" | cut -d: -f3)
        log "Active WiFi: $ACTIVE_WIFI_CONNECTION on $ACTIVE_WIFI_DEVICE"
    fi
fi

log_section "[2/9] Installing Required Packages"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Would install: certmonger, NetworkManager, wpa_supplicant, openssl, curl"
else
    case "$OS" in
        fedora|rhel|centos|rocky|almalinux)
            dnf install -y certmonger NetworkManager wpa_supplicant openssl curl &>/dev/null
            dnf install -y NetworkManager-wifi &>/dev/null || log "WiFi support not available"
            ;;
        debian|ubuntu)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y certmonger network-manager wpasupplicant openssl curl &>/dev/null
            ;;
        *)
            log_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac

    systemctl enable --now certmonger &>/dev/null

    echo "=== CERTMONGER STARTUP ==="
    log "Starting certmonger..."
    sleep 10

    systemctl restart certmonger
    sleep 5

    if ! getcert list &>/dev/null; then
        log_error "Certmonger not responding"
        exit 1
    fi
    log_success "Certmonger ready"

    if ! systemctl is-active --quiet certmonger; then
        log_error "Certmonger failed to start"
        systemctl status certmonger >> "$LOG_FILE" 2>&1
        exit 1
    fi
fi

log_success "Packages installed"

log_section "[3/9] SCEP Certificate Enrollment"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Would create directory: $CERT_BASE_PATH"
    log "[TEST] Would download SCEP server TLS CA certificate"
    log "[TEST] Would configure SCEP CA: $CA_NAME"
    log "[TEST] Would request certificate for: $FQDN"
    log "[TEST] Would wait for certificate enrollment (max 180 sec)"
    log "[TEST] Would verify private key has no passphrase"
else
    mkdir -p "$CERT_BASE_PATH"
    chmod 700 "$CERT_BASE_PATH"

    # Configure SCEP CA with TLS certificate download
    if ! getcert list-cas 2>/dev/null | grep -q "^CA '$CA_NAME'"; then
        if ! configure_scep_ca; then
            log_error "Failed to configure SCEP CA"
            exit 1
        fi
    else
        log "SCEP CA already configured"
    fi

    log "Checking for old certificate requests..."

    ALL_REQUESTS=$(getcert list 2>/dev/null | grep "Request ID" | awk '{print $3}' | tr -d "'" || true)

    if [ -n "$ALL_REQUESTS" ]; then
        CLEANED_COUNT=0

        while IFS= read -r REQ_ID; do
            [ -z "$REQ_ID" ] && continue

            REQ_CA=$(getcert list -i "$REQ_ID" 2>/dev/null | grep "^[[:space:]]*CA:" | awk '{print $2}' || true)
            REQ_SUBJECT=$(getcert list -i "$REQ_ID" 2>/dev/null | grep "^[[:space:]]*subject:" | cut -d: -f2- || true)

            if [[ "$REQ_CA" == "$CA_NAME" ]] && [[ "$REQ_SUBJECT" == *"$HOSTNAME"* || "$REQ_SUBJECT" == *"$FQDN"* ]]; then

                if [[ "$REQ_ID" == "enterprise-8021x-${HOSTNAME}" ]]; then
                    log "  Keeping: $REQ_ID (canonical certificate)"
                    continue
                fi

                log_warn "  Removing old certificate request: $REQ_ID"
                getcert stop-tracking -i "$REQ_ID" 2>/dev/null || true
                CLEANED_COUNT=$((CLEANED_COUNT + 1))
            fi
        done <<< "$ALL_REQUESTS"

        if [ $CLEANED_COUNT -gt 0 ]; then
            log_success "Cleaned up $CLEANED_COUNT old certificate request(s)"
        fi
    fi

    REQUEST_ID="enterprise-8021x-${HOSTNAME}"
    CERT_ENROLLED=false

    if getcert list -i "$REQUEST_ID" 2>/dev/null | grep -q "status: MONITORING"; then
        if [ -f "$MACHINE_CERT" ] && [ -f "$MACHINE_KEY" ]; then
            log "Certificate already enrolled and valid"
            CERT_ENROLLED=true
        else
            log "Certificate tracking exists but files missing"
            getcert stop-tracking -i "$REQUEST_ID" 2>/dev/null || true
        fi
    fi

    if [ "$CERT_ENROLLED" = false ]; then
        getcert stop-tracking -i "$REQUEST_ID" 2>/dev/null || true
        rm -f "$MACHINE_CERT" "$MACHINE_KEY"

        log "Requesting certificate for: $FQDN"

        getcert request             -c "$CA_NAME"             -I "$REQUEST_ID"             -k "$MACHINE_KEY"             -f "$MACHINE_CERT"             -N "CN=$FQDN"             -D "$FQDN"             -r

        record_state "CERT_REQUESTED:$REQUEST_ID"

        log "Waiting for certificate (max 180 sec)..."

        TIMEOUT=180
        ELAPSED=0

        while [ $ELAPSED -lt $TIMEOUT ]; do
            sleep 3
            ELAPSED=$((ELAPSED + 3))

            STATUS=$(getcert list -i "$REQUEST_ID" 2>/dev/null | grep "status:" | awk '{print $2}')

            case "$STATUS" in
                MONITORING)
                    log_success "Certificate enrolled successfully!"
                    break
                    ;;
                CA_REJECTED)
                    log_error "Certificate REJECTED by NDES"
                    getcert list -i "$REQUEST_ID" >> "$LOG_FILE" 2>&1
                    log_error "Check NDES logs and enrollment permissions"
                    exit 1
                    ;;
                CA_UNREACHABLE)
                    log_error "CA UNREACHABLE"
                    getcert list -i "$REQUEST_ID" >> "$LOG_FILE" 2>&1
                    exit 1
                    ;;
                NEED_GUIDANCE|SUBMITTING)
                    ;;
                *)
                    if [ $((ELAPSED % 15)) -eq 0 ]; then
                        log "Current status: $STATUS (waiting...)"
                    fi
                    ;;
            esac
        done

        if [ "$STATUS" != "MONITORING" ]; then
            log_error "Certificate enrollment timeout"
            log_error "Final status: $STATUS"
            getcert list -i "$REQUEST_ID" >> "$LOG_FILE" 2>&1
            exit 1
        fi
    fi

    chmod 644 "$MACHINE_CERT"
    chmod 600 "$MACHINE_KEY"

    log "Verifying private key has no passphrase..."
    if openssl rsa -in "$MACHINE_KEY" -check -noout &>/dev/null; then
        log_success "Private key verified (no passphrase, readable)"
    else
        log_error "Private key is not readable or has passphrase"
        log_error "This will prevent NetworkManager from using the certificate"
        exit 1
    fi

    log "Certificate: $MACHINE_CERT"
    log "Private Key: $MACHINE_KEY"

    CERT_SUBJECT=$(openssl x509 -in "$MACHINE_CERT" -noout -subject | sed 's/subject=//')
    CERT_EXPIRES=$(openssl x509 -in "$MACHINE_CERT" -noout -enddate | sed 's/notAfter=//')
    log "  Subject: $CERT_SUBJECT"
    log "  Expires: $CERT_EXPIRES"
fi

log_section "[4/9] Extracting CA Certificate Chain"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Would download and extract CA certificate chain for 802.1x"
else
    if [ ! -f "$CA_CERT" ] || [ ! -s "$CA_CERT" ]; then
        log "Downloading CA certificate for 802.1x authentication..."

        # Try HTTPS first, fallback to HTTP
        SCEP_GET_CA_URL="${SCEP_URL}?operation=GetCACert&message=0"

        if ! timeout 30 curl -k -s "$SCEP_GET_CA_URL" -o /tmp/ndes-ca.p7b 2>/dev/null || [ ! -s /tmp/ndes-ca.p7b ]; then
            log_warn "HTTPS download failed, trying HTTP..."
            SCEP_GET_CA_URL=$(echo "$SCEP_GET_CA_URL" | sed 's|https://|http://|')

            if ! timeout 30 curl -s "$SCEP_GET_CA_URL" -o /tmp/ndes-ca.p7b 2>/dev/null; then
                log_error "Failed to download CA certificate"
                exit 1
            fi
        fi

        if [ ! -s /tmp/ndes-ca.p7b ]; then
            log_error "Downloaded CA certificate is empty"
            exit 1
        fi

        openssl pkcs7 -in /tmp/ndes-ca.p7b -inform DER -print_certs -out "$CA_CERT"

        if [ ! -s "$CA_CERT" ]; then
            log_error "Failed to extract CA certificates"
            exit 1
        fi

        chmod 644 "$CA_CERT"
        log_success "CA certificate saved for 802.1x"
    else
        log "CA certificate already exists"
    fi
fi

# Continue with remaining sections [5/9] through [9/9]...
# (Sections 5-9 remain exactly the same as version 2.5.2)

log_section "[5/9] Deprioritizing Old Indra WiFi Profiles"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Would scan for old Indra WiFi profiles"
    log "[TEST] Would set priority to $OLD_INDRA_PRIORITY for backup"
else
    ALL_WIFI_CONNECTIONS=$(nmcli -t -f NAME,TYPE connection show 2>/dev/null | grep ":wifi$" | cut -d: -f1 || true)

    if [ -n "$ALL_WIFI_CONNECTIONS" ]; then
        log "Scanning for old Indra WiFi profiles..."

        DEPRIORITIZED_COUNT=0

        while IFS= read -r WIFI_NAME; do
            [ -z "$WIFI_NAME" ] && continue

            WIFI_NAME_LOWER=$(echo "$WIFI_NAME" | tr '[:upper:]' '[:lower:]')

            if [[ "$WIFI_NAME_LOWER" == *"indra"* ]]; then

                if [[ "$WIFI_NAME" == "$WIFI_CONNECTION_NAME" ]]; then
                    continue
                fi

                log "  Deprioritizing: $WIFI_NAME"

                if nmcli connection modify "$WIFI_NAME"                     connection.autoconnect-priority $OLD_INDRA_PRIORITY                     connection.autoconnect yes 2>/dev/null; then
                    DEPRIORITIZED_COUNT=$((DEPRIORITIZED_COUNT + 1))
                fi
            fi
        done <<< "$ALL_WIFI_CONNECTIONS"

        if [ $DEPRIORITIZED_COUNT -gt 0 ]; then
            log_success "Deprioritized $DEPRIORITIZED_COUNT old profile(s)"
        fi
    fi
fi

log_section "[6/9] Preserving Existing Connections"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Would preserve existing wired/WiFi connections as fallback"
else
    if [ -n "$ACTIVE_WIRED_CONNECTION" ] && [[ "$ACTIVE_WIRED_CONNECTION" != "$WIRED_CONNECTION_NAME" ]]; then
        log "Preserving: $ACTIVE_WIRED_CONNECTION"
        nmcli connection modify "$ACTIVE_WIRED_CONNECTION"             connection.autoconnect-priority $EXISTING_FALLBACK_PRIORITY             connection.autoconnect true 2>/dev/null || true
    fi

    if [ -n "$ACTIVE_WIFI_CONNECTION" ] && [[ "$ACTIVE_WIFI_CONNECTION" != "$WIFI_CONNECTION_NAME" ]]; then
        log "Preserving: $ACTIVE_WIFI_CONNECTION"
        nmcli connection modify "$ACTIVE_WIFI_CONNECTION"             connection.autoconnect-priority $EXISTING_FALLBACK_PRIORITY             connection.autoconnect yes 2>/dev/null || true
    fi
fi

log_section "[7/9] Configuring Wired 802.1x"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Would detect wired interfaces"
    log "[TEST] Would create/update wired 802.1x profile with priority $WIRED_PRIORITY"
    log "[TEST] Private key password flags: not-required (4)"
else
    WIRED_INTERFACES=$(nmcli -t -f DEVICE,TYPE device 2>/dev/null | grep ethernet | cut -d: -f1 || true)

    if [ -z "$WIRED_INTERFACES" ]; then
        log "No wired interfaces found"
    else
        log "Found wired interfaces: $(echo $WIRED_INTERFACES | tr '
' ' ')"

        WIRED_INTERFACE=$(echo "$WIRED_INTERFACES" | head -1)
        log "Using: $WIRED_INTERFACE"

        SKIP_WIRED_ACTIVATION=false

        if [ -n "$ACTIVE_WIRED_CONNECTION" ] && [[ "$ACTIVE_WIRED_CONNECTION" != "$WIRED_CONNECTION_NAME" ]]; then
            log_warn "Interface active with: $ACTIVE_WIRED_CONNECTION"
            log_warn "Will NOT activate to avoid disruption"
            SKIP_WIRED_ACTIVATION=true
        fi

        if nmcli connection show "$WIRED_CONNECTION_NAME" &>/dev/null; then
            CURRENT_CERT=$(nmcli -t -f 802-1x.client-cert con show "$WIRED_CONNECTION_NAME" 2>/dev/null | cut -d: -f2- || true)

            if [[ "$CURRENT_CERT" == "file://$MACHINE_CERT" ]]; then
                log "Wired 802.1x already configured correctly"
            else
                log "Recreating with updated certificate..."
                nmcli connection delete "$WIRED_CONNECTION_NAME" >> "$LOG_FILE" 2>&1 || true
            fi
        fi

        if ! nmcli connection show "$WIRED_CONNECTION_NAME" &>/dev/null; then
            log "Creating wired 802.1x profile (certificate-based, no password)..."

            nmcli connection add                 type ethernet                 con-name "$WIRED_CONNECTION_NAME"                 ifname "$WIRED_INTERFACE"                 autoconnect yes                 connection.autoconnect-priority $WIRED_PRIORITY                 802-1x.eap "$EAP_METHOD"                 802-1x.identity "host/$FQDN"                 802-1x.client-cert "file://$MACHINE_CERT"                 802-1x.private-key "file://$MACHINE_KEY"                 802-1x.private-key-password ""                 802-1x.private-key-password-flags 4                 802-1x.ca-cert "file://$CA_CERT"                 ipv4.method auto                 ipv6.method auto >> "$LOG_FILE" 2>&1

            record_state "CONNECTION_CREATED:$WIRED_CONNECTION_NAME"
            log_success "Wired 802.1x configured (private-key-password-flags: not-required)"
        fi

        if [ "$SKIP_WIRED_ACTIVATION" = false ]; then
            log "Attempting to activate 802.1x profile..."
            if nmcli connection up "$WIRED_CONNECTION_NAME" >> "$LOG_FILE" 2>&1; then
                log_success "Wired 802.1x activated successfully"
            else
                log_warn "Could not activate now (expected if not on 802.1x network)"
                log "Profile will auto-activate when connected to 802.1x switch"
            fi
        else
            log "Profile ready - will auto-activate on 802.1x network"
        fi
    fi
fi

log_section "[7A/9] Ensuring Ethernet is Managed"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Would check /etc/network/interfaces (Debian/Ubuntu)"
    log "[TEST] Would ensure all ethernet interfaces are managed"
else
    if [[ "$OS" == "debian" || "$OS" == "ubuntu" ]] && [ -f /etc/network/interfaces ]; then
        log "Checking /etc/network/interfaces..."

        if grep -qE "^[[:space:]]*(auto|allow-hotplug|iface)[[:space:]]+e(ns|th|np)[0-9]" /etc/network/interfaces; then
            log_warn "Ethernet interfaces found in /etc/network/interfaces"

            BACKUP_FILE="/etc/network/interfaces.backup-$(date +%Y%m%d-%H%M%S)"
            cp /etc/network/interfaces "$BACKUP_FILE"
            cp /etc/network/interfaces /etc/network/interfaces.backup-rollback
            record_state "FILE_MODIFIED:/etc/network/interfaces"

            log "Backed up to: $BACKUP_FILE"

            sed -i                 -e '/^[[:space:]]*\(auto\|allow-hotplug\|iface\)[[:space:]]\+e\(ns\|th\|np\)[0-9]/s/^/# DISABLED: /'                 /etc/network/interfaces

            log_success "Disabled ethernet in /etc/network/interfaces"

            if systemctl is-active --quiet networking; then
                systemctl stop networking 2>/dev/null || true
            fi

            systemctl restart NetworkManager
            sleep 5
        fi
    fi

    if [ -n "$WIRED_INTERFACES" ]; then
        for WIRED_IF in $WIRED_INTERFACES; do
            IF_STATE=$(nmcli -t -f DEVICE,STATE device status 2>/dev/null | grep "^${WIRED_IF}:" | cut -d: -f2 || echo "unknown")

            if [ "$IF_STATE" = "unmanaged" ] || [ "$IF_STATE" = "uhåndteret" ]; then
                log_warn "Interface $WIRED_IF is unmanaged - fixing"
                nmcli device set "$WIRED_IF" managed yes 2>/dev/null || true
                sleep 3
            fi
        done
    fi
fi

log_section "[8/9] Configuring WiFi"

if [ "$TEST_MODE" = true ]; then
    log "[TEST] Would detect WiFi interfaces"
    log "[TEST] Would create IndraNavia 802.1x profile with priority $WIFI_PRIORITY"
    log "[TEST] Would detect if SSID is hidden or visible"
    log "[TEST] Private key password flags: not-required (4)"
else
    WIFI_INTERFACES=$(nmcli -t -f DEVICE,TYPE device 2>/dev/null | grep wifi | cut -d: -f1 || true)

    if [ -z "$WIFI_INTERFACES" ]; then
        log "No WiFi interfaces found"
    else
        log "Found WiFi interfaces: $(echo $WIFI_INTERFACES | tr '
' ' ')"

        WIFI_INTERFACE=$(echo "$WIFI_INTERFACES" | head -1)

        nmcli radio wifi on &>/dev/null
        sleep 2

        SKIP_WIFI_ACTIVATION=false

        if [ -n "$ACTIVE_WIFI_CONNECTION" ] && [[ "$ACTIVE_WIFI_CONNECTION" != "$WIFI_CONNECTION_NAME" ]]; then
            log_warn "WiFi active with: $ACTIVE_WIFI_CONNECTION"
            log_warn "Will NOT activate to avoid disruption"
            SKIP_WIFI_ACTIVATION=true
        fi

        log "Scanning for networks..."
        nmcli device wifi rescan ifname "$WIFI_INTERFACE" &>/dev/null || true
        sleep 3

        SSID_HIDDEN="yes"
        if nmcli device wifi list ifname "$WIFI_INTERFACE" 2>/dev/null | grep -qw "$WIFI_SSID"; then
            SSID_HIDDEN="no"
            log_success "$WIFI_SSID is visible"
        else
            log "$WIFI_SSID not visible (hidden or out of range)"
        fi

        if nmcli connection show "$WIFI_CONNECTION_NAME" &>/dev/null; then
            CURRENT_CERT=$(nmcli -t -f 802-1x.client-cert con show "$WIFI_CONNECTION_NAME" 2>/dev/null | cut -d: -f2- || true)

            if [[ "$CURRENT_CERT" == "file://$MACHINE_CERT" ]]; then
                log "WiFi 802.1x already configured correctly"
            else
                nmcli connection delete "$WIFI_CONNECTION_NAME" >> "$LOG_FILE" 2>&1 || true
            fi
        fi

        if ! nmcli connection show "$WIFI_CONNECTION_NAME" &>/dev/null; then
            log "Creating IndraNavia 802.1x profile (certificate-based, no password)..."

            nmcli connection add                 type wifi                 con-name "$WIFI_CONNECTION_NAME"                 ifname "$WIFI_INTERFACE"                 ssid "$WIFI_SSID"                 autoconnect yes                 connection.autoconnect-priority $WIFI_PRIORITY                 wifi.hidden "$SSID_HIDDEN"                 wifi-sec.key-mgmt wpa-eap                 802-1x.eap "$EAP_METHOD"                 802-1x.identity "host/$FQDN"                 802-1x.client-cert "file://$MACHINE_CERT"                 802-1x.private-key "file://$MACHINE_KEY"                 802-1x.private-key-password ""                 802-1x.private-key-password-flags 4                 802-1x.ca-cert "file://$CA_CERT"                 ipv4.method auto                 ipv6.method auto >> "$LOG_FILE" 2>&1

            record_state "CONNECTION_CREATED:$WIFI_CONNECTION_NAME"
            log_success "WiFi 802.1x configured (private-key-password-flags: not-required)"
        fi

        if [ "$SKIP_WIFI_ACTIVATION" = false ]; then
            log "Attempting to activate WiFi profile..."
            if nmcli connection up "$WIFI_CONNECTION_NAME" >> "$LOG_FILE" 2>&1; then
                log_success "WiFi activated successfully"
            else
                log_warn "Could not activate now (expected if SSID out of range)"
                log "Profile will auto-activate when in range"
            fi
        else
            log "Profile ready - will auto-activate when in range"
        fi
    fi
fi

log_section "[9/9] Final Verification"

verify_deployment

if [ "$TEST_MODE" = false ]; then
    echo "SUCCESS: Enterprise network deployed on $(hostname). Log: $LOG_FILE"
else
    echo ""
    echo "=== TEST MODE SUMMARY ==="
    echo "Test completed successfully"
    echo "Script would:"
    echo "  - Download SCEP server TLS CA certificate"
    echo "  - Configure SCEP CA (HTTPS with -R flag OR HTTP fallback)"
    echo "  - Install NetworkManager and dependencies"
    echo "  - Request SCEP certificate for: $FQDN"
    echo "  - Verify private key has no passphrase"
    echo "  - Create Wired-802.1x profile (priority: $WIRED_PRIORITY)"
    echo "  - Create IndraNavia WiFi profile (priority: $WIFI_PRIORITY)"
    echo "  - Set private-key-password-flags to 'not-required' (flag 4)"
    echo "  - Deprioritize old Indra profiles (priority: $OLD_INDRA_PRIORITY)"
    echo "  - Preserve existing connections (priority: $EXISTING_FALLBACK_PRIORITY)"
    echo ""
    echo "Run without --test to deploy"
fi