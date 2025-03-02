#!/usr/bin/env bash
#
# Description:
#   This script acts as a Fail2Ban `actionstart|actionban` to report offending IPs to AbuseIPDB.
#   It allows for 'custom comments' to prevent leaking sensitive information. The main goal is to
#   avoid relying on Fail2Ban and instead use a local banned IP list for complete isolation.
#   It can also be used with Fail2Ban's `norestored=1` feature to rely on Fail2Ban for preventing
#   redundant report actions on restarts. Users can toggle this behavior as needed.
#
#   The script performs two API calls for each ban action:
#     1. **/v2/check**  - Checks if the IP has already been reported.
#     2. **/v2/report** - Reports the IP if necessary and updates the local banned IP list.
#   These two endpoints have separate daily limits, so they do not impact your reporting quota.
#
#   To view any failures, check `/var/log/abuseipdb/abuseipdb.log`.
#
# Integration with Fail2Ban:
#   1. Edit only 'abuseipdb.local' in 'action.d/abuseipdb.local' and uncomment pre-configured settings.
#   2. Adjust your jails to prevent leaking sensitive information in custom comments via 'tp_comment'.
#
# Example 'jail' configuration in 'jail.local' to prevent leaking sensitive information in AbuseIPDB reports:
#   [nginx-botsearch]
#   enabled    = true
#   logpath    = /var/log/nginx/*.log
#   port       = http,https
#   backend    = polling
#   tp_comment = Fail2Ban - NGINX bad requests 400-401-403-404-444, high level vulnerability scanning
#   maxretry   = 3
#   findtime   = 1d
#   bantime    = 7200
#   action     = %(action_mwl)s
#                %(action_abuseipdb)s[matches="%(tp_comment)s", abuseipdb_apikey="YOUR_API_KEY", abuseipdb_category="21,15", bantime="%(bantime)s"]
#
# Usage:
#   This script is designed to be triggered automatically by Fail2Ban (`actionstart|actionban`).
#   Manual Usage:
#    - For testing purpose before production;
#       /etc/fail2ban/action.d/fail2ban_abuseipdb.sh "your_api_key" "Failed SSH login attempts" "192.0.2.1" "18" "600"
#
# Arguments:
#   $1 APIKEY          - Required (Core). Retrieved automatically from the Fail2Ban 'jail'.        | Your AbuseIPDB API key.
#   $2 COMMENT         - Required (Core). Retrieved automatically from the Fail2Ban 'jail'.        | A custom comment to prevent the leakage of sensitive data when reporting
#   $3 IP              - Required (Core). Retrieved automatically from the Fail2Ban 'jail'.        | The IP address to report.
#   $4 CATEGORIES      - Required (Core). Retrieved automatically from the Fail2Ban 'jail'.        | Abuse categories as per AbuseIPDB's API
#   $5 BANTIME         - Required (Core). Retrieved automatically from the Fail2Ban 'jail'.        | Ban duration
#   $6 RESTORED        - Required (Core). Retrieved automatically from the Fail2Ban '<restored>'   | Status of restored tickets
#   $7 BYPASS_FAIL2BAN - Required (User defined). Must be defined in 'action.d/abuseipdb.local'.   | Bypassing Fail2Ban on restarts
#   $8 LOCAL_LIST      - Required (User defined). Must be defined in 'action.d/abuseipdb.local'.   | Path to the main banned IP list used by the script
#   $9 LOG_FILE        - Required (User defined). Must be defined in 'action.d/abuseipdb.local'.   | Path to the log file where actions and events are recorded by the script
#
# Dependencies:
#   curl: For making API requests to AbuseIPDB.
#   jq: For parsing JSON responses.
#   flock: Prevent data corruption.
#
# Return Codes:
#   0 - 'AbuseIPDB' IP is reported.
#   1 - 'AbuseIPDB' IP is not reported.
#
# Exit Codes:
#   0 - 'norestored'  restored tickets enabled.
#   0 - 'actionstart' tasks completed.
#   1 - 'actionstart' tasks cannot completed and lock file created.
#   1 - 'AbuseIPDB'   API-related failure.
#
# Author:
#   Hasan ÇALIŞIR
#   hasan.calisir@psauxit.com
#   https://github.com/hsntgm

# This script is used for both: 'actionstart' and 'actionban' in 'action.d/abuseipdb.local'
# It dynamically assigns arguments based on the action type
# and provides default values for missing user settings to prevent failures.
APIKEY="$1"
COMMENT="$2"
IP="$3"
CATEGORIES="$4"
BANTIME="$5"
RESTORED="${6}"
BYPASS_FAIL2BAN="${7:-0}"
if [[ "$1" == "--actionstart" ]]; then
    # When triggered by 'actionstart'
    REPORTED_IP_LIST_FILE="${2:-/var/log/abuseipdb/abuseipdb-banned.log}"
    LOG_FILE="${3:-/var/log/abuseipdb/abuseipdb.log}"
else
    # When triggered by 'actionban'
    REPORTED_IP_LIST_FILE="${8:-/var/log/abuseipdb/abuseipdb-banned.log}"
    LOG_FILE="${9:-/var/log/abuseipdb/abuseipdb.log}"
fi

# Log messages
log_message() {
    local message="$1"
    echo "$(date +"%Y-%m-%d %H:%M:%S") - ${message}" >> "${LOG_FILE}"
}

# Define lock file
LOCK_FILE="/tmp/abuseipdb_actionstart.lock"

# Function to remove lock file if it exists
remove_lock() {
    if [[ -f "${LOCK_FILE}" ]]; then
        rm -f "${LOCK_FILE:?}"
    fi
}

# Function to create lock file
create_lock() {
    if [[ ! -f "${LOCK_FILE}" ]]; then
        touch "${LOCK_FILE}"
    fi
}

# Check if the script was triggered by 'actionstart' early in execution.
# This ensures necessary checks is performed before proceeding only once.
# This check runs on background always with 'nohup' to prevent latency.
# We listen exit codes carefully to allow or not further runtime 'actionban' events
if [[ "$1" == "--actionstart" ]]; then
    # Trap exit signal to create/remove lock file based on exit status
    trap 'if [[ $? -ne 0 ]]; then create_lock; else remove_lock; fi' EXIT

    # Ensure the directory for the reported IP list exists
    LOG_DIR=$(dirname "${REPORTED_IP_LIST_FILE}")
    if [[ ! -d "${LOG_DIR}" ]]; then
        mkdir -p "${LOG_DIR}" || exit 1
    fi

    # Ensure the reported IP list and log file exist
    for file in "${REPORTED_IP_LIST_FILE}" "${LOG_FILE}"; do
        if [[ ! -f "${file}" ]]; then
            touch "${file}" || exit 1
        fi
    done

    # Check runtime dependencies
    dependencies=("curl" "jq" "flock")
    for dep in "${dependencies[@]}"; do
        if ! command -v "${dep}" &>/dev/null; then
            log_message "FATAL: -${dep} is not installed. Please install -${dep} to proceed."
            exit 1
        fi
    done

    # Tasks completed, quit nicely
    exit 0
fi

# If the 'actionstart' failed, prevent 'actionban'.
# This stops 'actionban' from being triggered during runtime due to missing dependencies or permission issues.
# A failed initial 'actionstart' check indicates a failure to report to AbuseIPDB.
if [[ -f "${LOCK_FILE}" ]]; then
    if [[ -f "${LOG_FILE}" ]]; then
        log_message "FATAL: Failed due to a permission issue or missing dependency. Reporting to AbuseIPDB failed."
        exit 1
    else
        exit 1
    fi
fi

# If 'BYPASS_FAIL2BAN' is disabled, Fail2Ban will be relied upon during restarts.
# This prevents duplicate reports when Fail2Ban is restarted.
# This setting is 'OPTIONAL' and can be overridden in 'action.d/abuseipdb.local'.
# If enabled, Fail2Ban is bypassed completely,
# and script takes full control to determine which IP to report based on
# the local banned IP list even on Fail2Ban restarts.
if [[ "${BYPASS_FAIL2BAN}" -eq 0 ]]; then
    if [[ "${RESTORED}" -eq 1 ]]; then
        log_message "INFO NORESTORED: IP ${IP} has already been reported. No duplicate report made after restart."
        exit 0
    fi
fi

# Validate core arguments: Ensure all required core args are provided.
# These values are expected to be passed by Fail2Ban 'jail' during execution.
# Also for manual testing purpose before production.
if [[ -z "$1" || -z "$2" || -z "$3" || -z "$4" || -z "$5" ]]; then
    log_message "FATAL: Missing core argument"
    exit 1
fi

# Function to check if the IP is listed on AbuseIPDB
check_ip_in_abuseipdb() {
    local response http_status body total_reports
    local delimiter="HTTP_STATUS:"

    # Perform the API call and capture both response and HTTP status
    response=$(curl -s -w "${delimiter}%{http_code}" -G "https://api.abuseipdb.com/api/v2/check" \
        --data-urlencode "ipAddress=${IP}" \
        -H "Key: ${APIKEY}" \
        -H "Accept: application/json" 2>&1)

    if [[ $? -ne 0 ]]; then
        log_message "ERROR CHECK: API failure. Response: ${response}"
        exit 1
    fi

    # Separate the HTTP status code from the response body
    http_status=$(echo "${response}" | tr -d '\n' | sed -e "s/.*${delimiter}//")
    body=$(echo "${response}" | sed -e "s/${delimiter}[0-9]*//")

    # Handle different HTTP status codes
    if [[ "${http_status}" =~ ^[0-9]+$ ]]; then
        # Handle rate-limiting (HTTP 429)
        if [[ "${http_status}" -eq 429 ]]; then
            log_message "ERROR CHECK: API returned HTTP 429 (Too Many Requests). Response: ${body}"
            exit 1
        fi

        # Handle other non-200 responses
        if [[ "${http_status}" -ne 200 ]]; then
            log_message "ERROR CHECK: API returned HTTP status ${http_status}. Response: ${body}"
            exit 1
        fi
    fi

    # Extract totalReports
    total_reports=$(echo "${body}" | jq '.data.totalReports')

    # Finally, check the IP listed on AbuseIPDB
    if [[ "${total_reports}" -gt 0 ]]; then
        return 0 # IP is reported
    else
        return 1 # IP is not reported
    fi
}

# Function to report AbuseIpDB
report_ip_to_abuseipdb() {
    local response
    response=$(curl --fail -s 'https://api.abuseipdb.com/api/v2/report' \
        -H 'Accept: application/json' \
        -H "Key: ${APIKEY}" \
        --data-urlencode "comment=${COMMENT}" \
        --data-urlencode "ip=${IP}" \
        --data "categories=${CATEGORIES}" 2>&1)

    # API call fail
    if [[ $? -ne 0 ]]; then
        log_message "ERROR REPORT: API failure. Response: ${response}"
        exit 1
    else
        log_message "SUCCESS REPORT: Reported IP ${IP} to AbuseIPDB. Local list updated."
    fi
}


# Set defaults
is_found_local=0
shouldBanIP=1

# Should Ban IP
if grep -m 1 -q -E "^IP=${IP}[[:space:]]+L=[0-9\-]+" "${REPORTED_IP_LIST_FILE}"; then
    # IP found locally, check if it's still listed on AbuseIPDB
    if check_ip_in_abuseipdb; then
        # IP is still listed on AbuseIPDB, no need to report again
        log_message "INFO: IP ${IP} has already been reported and remains on AbuseIPDB. No duplicate report made."
        shouldBanIP=0
    else
        # IP is reported before but not listed on AbuseIPDB, report it again
        log_message "INFO: IP ${IP} has already been reported but is no longer listed on AbuseIPDB. Reporting it again."
        shouldBanIP=1
        is_found_local=1
    fi
else
    shouldBanIP=1
fi

# Let's report to AbuseIpdb
if [[ "${shouldBanIP}" -eq 1 ]]; then
    # Add the new ban entry to local list kindly
    if [[ "${is_found_local}" -eq 0 ]]; then
        exec 200<> "${REPORTED_IP_LIST_FILE}"                      # Open with read/write access
        flock -x 200                                               # Lock
        echo "IP=${IP} L=${BANTIME}" >> "${REPORTED_IP_LIST_FILE}" # Write
        flock -u 200                                               # Release the lock
        exec 200>&-                                                # Close the file descriptor
    fi

    # Report IP
    report_ip_to_abuseipdb
fi
