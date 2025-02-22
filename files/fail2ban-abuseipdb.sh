#!/usr/bin/env bash
#
# Description:
#   This script serves as a Fail2Ban `actionban` to report offending IP addresses to AbuseIPDB with custom COMMENTS.
#   Mainly whenever Fail2Ban restarts, it calls the actionban function for each IP stored in the database file.
#   If you restart your server often this script prevents duplicate reporting to AbuseIPDB by maintaining a local list of already reported IPs.
#   Before reporting, it checks both the local list and AbuseIPDB to ensure the IP hasn't
#   been reported previously, thereby avoiding redundant entries and potential API rate limiting.
#
# Integration with Fail2Ban:
#   - Place this script in the 'action.d' directory of Fail2Ban.
#   - Configure Fail2Ban to use this script as the `actionban`.
#   - First edit 'abuseipdb.conf' in '/etc/fail2ban/action.d/abuseipdb.conf' and add following rule,
#   - actionban = /etc/fail2ban/action.d/fail2ban-abuseipdb.sh \
#         "<abuseipdb_apikey>" "<matches>" "<ip>" "<abuseipdb_category>" "<bantime>"
#   - Also make sure you set your 'abuseipdb_apikey' in the configuration file.
#   - Adjust your jails accordingly. Check the below jail example to also reporting with custom comment via  'tp_comment'
#
#   Example jail in 'jail.local':
#     [nginx-botsearch]
#     enabled    = true
#     logpath    = /var/log/nginx/*.log
#     port       = http,https
#     backend    = polling
#     tp_comment = Fail2Ban - NGINX bad requests 400-401-403-404-444, high level vulnerability scanning, commonly xmlrpc_attack, wp-login brute force, excessive crawling/scraping
#     maxretry   = 3
#     findtime   = 1d
#     bantime    = 7200
#     action     = %(action_mwl)s
#                  %(action_abuseipdb)s[matches="%(tp_comment)s", abuseipdb_apikey="YOUR_API_KEY", abuseipdb_category="21,15", bantime="%(bantime)s"]
#
#   Start from scratch practise:
#     - Stop Fail2ban
#     - Clear all existing firewall reject rules from iptables
#     - Delete Fail2ban SQLite database and truncate fail2ban.log
#     - Force logrotate
#     - Follow above implementation steps and adjust all your jails accordingly
#     - Start Fail2ban
#
# Usage:
#   This script is intended to be called by Fail2Ban automatically (actionban) and accepts the following arguments:
#     1. <APIKEY>     - Your AbuseIPDB API key.
#     2. <COMMENT>    - A comment describing the reason for reporting the IP.
#     3. <IP>         - The IP address to report.
#     4. <CATEGORIES> - Comma-separated list of abuse categories as per AbuseIPDB's API.
#     5. <BANTIME>    - Duration for which the IP should be banned (e.g., 600 for 10 minutes).
#
#   Manual Usage:
#     For testing purpose before production;
#       /etc/fail2ban/action.d/abuseipdb_fail2ban_actionban.sh "your_api_key" "Failed SSH login attempts" "192.0.2.1" "18" "600"
#
# Arguments:
#   APIKEY      - Required.
#   COMMENT     - Required.
#   IP          - Required.
#   CATEGORIES  - Required.
#   BANTIME     - Required.
#
# Configurations (Need to set):
#   - REPORTED_IP_LIST_FILE: Path to the local file storing reported IPs and their ban times.
#   - LOG_FILE: Path to the log file where actions and events are recorded.
#
# Dependencies:
#   - curl: For making API requests to AbuseIPDB.
#   - jq: For parsing JSON responses.
#   - flock: Prevent data corruption.
#
# General Considerations:
#   - The script does not interact with or rely on Fail2Ban’s SQLite database, as the Fail2ban database setup can vary across different environments.
#   - The script performs two API calls to AbuseIPDB for each ban action in order to determine whether the IP should be reported.
#   - First Call:  /v2/check → Checks if the IP is already reported.
#   - Second Call: /v2/report → Reports the IP if necessary.
#   - These two endpoints have separate daily limits, so does not affect your reporting quota.
#   - When multiple instances of the script try to write to the REPORTED_IP_LIST_FILE concurrently we need to prevent data corruption. 'flock' used for that reason.
#   - Never delete, truncate or try to sync REPORTED_IP_LIST_FILE with Fail2ban SQLite.
#   - Even you reset fail2ban SQLite, continue to keep REPORTED_IP_LIST_FILE same, It serves as the script’s local tracking system.
#   - When you go production keep watching '/var/log/abuseipdb-report.log' for any abnormal fails.
#
# Return Codes:
#   0 - IP is reported
#   1 - IP is not reported
#
# Exit Codes:
#   1 - API-related failure
#
# Author:
#   Hasan ÇALIŞIR - PSAUXIT
#   hasan.calisir@psauxit.com
#   https://www.psauxit.com/

# Arguments
APIKEY="$1"
COMMENT="$2"
IP="$3"
CATEGORIES="$4"
BANTIME="$5"

# Configuration
REPORTED_IP_LIST_FILE="/etc/fail2ban/action.d/abuseipdb-reported-ip-list"
LOG_FILE="/var/log/abuseipdb-report.log"

# Set defaults
is_found_local=0
shouldBanIP=1

# Log messages
log_message() {
    local message="$1"
    echo "$(date +"%Y-%m-%d %H:%M:%S") - ${message}" >> "${LOG_FILE}"
}

# Arguments validation
if [[ -z "$1" || -z "$2" || -z "$3" || -z "$4" || -z "$5" ]]; then
    log_message "FATAL: Usage: $0 <APIKEY> <COMMENT> <IP> <CATEGORIES> <BANTIME>"
    exit 1
fi

# Ensure the directory for the reported IP list exists
REPORTED_IP_DIR=$(dirname "${REPORTED_IP_LIST_FILE}")
if [[ ! -d "${REPORTED_IP_DIR}" ]]; then
    mkdir -p "${REPORTED_IP_DIR}" || { log_message "FATAL: Could not create directory ${REPORTED_IP_DIR}"; exit 1; }
fi

# Ensure the reported IP list file exists and is writable
if [[ ! -f "${REPORTED_IP_LIST_FILE}" ]]; then
    touch "${REPORTED_IP_LIST_FILE}" || { log_message "FATAL: Could not create file ${REPORTED_IP_LIST_FILE}"; exit 1; }
fi

if [[ ! -w "${REPORTED_IP_LIST_FILE}" ]]; then
    log_message "FATAL: File ${REPORTED_IP_LIST_FILE} is not writable."
    exit 1
fi

# Check runtime dependencies
dependencies=("curl" "jq" "flock")
for dep in "${dependencies[@]}"; do
    if ! command -v "${dep}" &>/dev/null; then
        log_message "FATAL: -${dep} is not installed. Please install -${dep} to proceed."
        exit 1
    fi
done

# Check if the IP is listed on AbuseIPDB
check_ip_in_abuseipdb() {
    local response http_status body total_reports error_detail
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

    # Check if the response body is empty
    if [[ -z "${body}" ]]; then
        log_message "ERROR CHECK: API response empty."
        exit 1
    fi

    # Validate that the response is valid JSON
    if ! echo "${body}" | jq . >/dev/null 2>&1; then
        log_message "ERROR CHECK: API response malformed. Response: ${body}"
        exit 1
    fi

    # Handle different HTTP status codes
    if [[ "${http_status}" =~ ^[0-9]+$ ]]; then
        if [[ "${http_status}" -ge 200 && "${http_status}" -lt 300 ]]; then
            # Successful HTTP response; check for API-level errors
            if echo "${body}" | jq -e '.errors | length > 0' >/dev/null 2>&1; then
                error_detail=$(echo "${body}" | jq -r '.errors[].detail')
                log_message "ERROR CHECK: API returned errors. Detail: ${error_detail}"
                exit 1
            fi
        else
            # Non-successful HTTP status
            log_message "ERROR CHECK: API returned ${http_status}. Response: ${body}"
            exit 1
        fi
    else
        log_message "ERROR CHECK: HTTP status '${http_status}' is not numeric."
        exit 1
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

# Report to AbuseIpDB
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
    # New comer, welcome to hell
    shouldBanIP=1
fi

# Report to AbuseIpdb
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
