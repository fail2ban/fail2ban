#!/usr/bin/env bash
#
# Description:
#   This script acts as a Fail2Ban `actionstart|actionban` to report offending IPs to AbuseIPDB.
#   It allows for 'custom comments' to prevent leaking sensitive information. The main goal is to
#   avoid relying on Fail2Ban and instead use a separate AbuseIPDB SQLite database for complete isolation.
#   It can also be used with Fail2Ban's `norestored=1` feature to rely on Fail2Ban for preventing
#   redundant reporting on restarts. Users can toggle this behavior as needed.
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
#   For testing (manual execution):
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
#   $2|$8 SQLITE_DB    - Required (User defined). Must be defined in 'action.d/abuseipdb.local'.   | Path to the main AbuseIPDB SQLite database
#   $3|$9 LOG_FILE     - Required (User defined). Must be defined in 'action.d/abuseipdb.local'.   | Path to the log file where actions and events are recorded by the script
#
# Dependencies:
#   curl: For making API requests to AbuseIPDB.
#   jq: For parsing JSON responses.
#   sqlite3: Local AbuseIPDB db.
#
# Author:
#   Hasan ÇALIŞIR
#   https://github.com/hsntgm

#######################################
# HELPERS: (START)
#######################################

APIKEY="$1"
COMMENT="$2"
IP="$3"
CATEGORIES="$4"
BANTIME="$5"
RESTORED="$6"
BYPASS_FAIL2BAN="${7:-0}"
if [[ "$1" == "--actionstart" ]]; then
    SQLITE_DB="${2:-/var/lib/fail2ban/abuseipdb/fail2ban_abuseipdb}"
    LOG_FILE="${3:-/var/log/abuseipdb/abuseipdb.log}"
else
    SQLITE_DB="${8:-/var/lib/fail2ban/abuseipdb/fail2ban_abuseipdb}"
    LOG_FILE="${9:-/var/log/abuseipdb/abuseipdb.log}"
fi

# Log messages
log_message() {
    local message="$1"
    echo "$(date +"%Y-%m-%d %H:%M:%S") - ${message}" >> "${LOG_FILE}"
}

# Lock files for 'actionstart' status
LOCK_BAN="/tmp/abuseipdb_actionstart.lock"
LOCK_DONE="/tmp/abuseipdb_actionstart.done"

# Remove lock file
remove_lock() {
    [[ -f "${LOCK_BAN}" ]] && rm -f "${LOCK_BAN}"
}

# Create lock file
create_lock() {
    [[ ! -f "${LOCK_BAN}" ]] && touch "${LOCK_BAN}"
}

# Pre-defined SQLite PRAGMAS
SQLITE_PRAGMAS="
    PRAGMA journal_mode=WAL;
    PRAGMA synchronous=NORMAL;
    PRAGMA temp_store=MEMORY;
    PRAGMA locking_mode=NORMAL;
    PRAGMA cache_size=-256000;
    PRAGMA busy_timeout=10000;
"

#######################################
# HELPERS: (END)
#######################################

#######################################
# ACTIONSTART: (START)
#######################################

########################################
#  Triggered by 'actionstart'
#  to perform necessary checks
#  and AbuseIPDB SQLite initialization.
#
# - Ensures required checks are done.
# - Runs in the background with 'nohup'
#   on initial start to prevent latency.
# - Listens for exit codes to control
#   further 'actionban' events via the
#   'lock' mechanism.
# - Check 'abuseipdb.local' for
#   integration details.
########################################

if [[ "$1" == "--actionstart" ]]; then
    if [[ ! -f "${LOCK_DONE}" ]]; then
        trap 'if [[ $? -ne 0 ]]; then create_lock; else remove_lock; fi' EXIT

        SQLITE_DIR=$(dirname "${SQLITE_DB}")
        if [[ ! -d "${SQLITE_DIR}" ]]; then
            mkdir -p "${SQLITE_DIR}" || exit 1
        fi

        if [[ ! -f "${LOG_FILE}" ]]; then
            touch "${LOG_FILE}" || exit 1
        fi

        for dep in curl jq sqlite3; do
            if ! command -v "${dep}" &>/dev/null; then
                log_message "ERROR: ${dep} is not installed. Please install ${dep}"
                exit 1
            fi
        done

        if [[ ! -f "${SQLITE_DB}" ]]; then
            sqlite3 "${SQLITE_DB}" "
                ${SQLITE_PRAGMAS}
                CREATE TABLE IF NOT EXISTS banned_ips (ip TEXT PRIMARY KEY, bantime INTEGER);
                CREATE INDEX IF NOT EXISTS idx_ip ON banned_ips(ip);
            "
        fi

        result=$(sqlite3 "file:${SQLITE_DB}?mode=ro" "SELECT name FROM sqlite_master WHERE type='table' AND name='banned_ips';")
        if ! [[ -n "${result}" ]]; then
            log_message "ERROR: AbuseIPDB database initialization failed."
            rm -f "${SQLITE_DB:?}"
            exit 1
        else
            log_message "SUCCESS: The AbuseIPDB database is now ready for connection."
        fi

        touch "${LOCK_DONE}" || exit 1
        exit 0
    else
        exit 0
    fi
fi

#######################################
# ACTIONSTART: (END)
#######################################

#######################################
# ACTIONBAN: (START)
#######################################

#######################################
# 1) Prevent 'actionban' if
# 'actionstart' fails.
#
# If 'actionstart' fails, block
# 'actionban' to prevent issues from
# missing dependencies or permission
# errors.
#######################################

#######################################
# 2) Fail2Ban restart handling &
# duplicate report prevention.
#
# - If 'BYPASS_FAIL2BAN' is disabled,
#   Fail2Ban manages reports on restart
#   and prevents duplicate submissions.
# - This setting can be overridden in
#   'action.d/abuseipdb.local'.
# - If enabled, Fail2Ban is bypassed,
#   and the script independently
#   decides which IPs to report based
#   on the AbuseIPDB db, even after
#   restarts.
#######################################

#######################################
# 3) Core argument validation
#
# - Ensures all required arguments
#   are provided.
# - Expected from Fail2Ban 'jail' or
#   for manual testing before
#   production deployment.
#######################################

#######################################
# EARLY CHECKS: (START)
#######################################

if [[ -f "${LOCK_BAN}" ]]; then
    [[ -f "${LOG_FILE}" ]] && log_message "ERROR: Initialization failed! (actionstart). Reporting for IP ${IP} is blocked."
    exit 1
fi

if [[ "${BYPASS_FAIL2BAN}" -eq 0 && "${RESTORED}" -eq 1 ]]; then
    log_message "INFO: IP ${IP} already reported."
    exit 0
fi

if [[ -z "${APIKEY}" || -z "${COMMENT}" || -z "${IP}" || -z "${CATEGORIES}" || -z "${BANTIME}" ]]; then
    log_message "ERROR: Missing core argument(s)."
    exit 1
fi

#######################################
# EARLY CHECKS: (END)
#######################################

#######################################
# FUNCTIONS: (START)
#######################################

check_ip_in_abuseipdb() {
    local response http_status body total_reports delimiter="HTTP_STATUS:"
    response=$(curl -s -w "${delimiter}%{http_code}" -G "https://api.abuseipdb.com/api/v2/check" \
        --data-urlencode "ipAddress=${IP}" \
        -H "Key: ${APIKEY}" \
        -H "Accept: application/json" 2>&1)

    if [[ $? -ne 0 ]]; then
        log_message "ERROR: API failure. Response: ${response}"
        return 1
    fi

    http_status=$(echo "${response}" | tr -d '\n' | sed -e "s/.*${delimiter}//")
    body=$(echo "${response}" | sed -e "s/${delimiter}[0-9]*//")

    if [[ "${http_status}" =~ ^[0-9]+$ ]]; then
        if [[ "${http_status}" -eq 429 ]]; then
            log_message "ERROR: Rate limited (HTTP 429). Response: ${body}"
            return 1
        fi

        if [[ "${http_status}" -ne 200 ]]; then
            log_message "ERROR: HTTP ${http_status}. Response: ${body}"
            return 1
        fi
    else
        log_message "ERROR: API failure. Response: ${response}"
        return 1
    fi

    total_reports=$(echo "${body}" | jq '.data.totalReports')
    if [[ "${total_reports}" -gt 0 ]]; then
        return 0
    else
        return 1
    fi
}

report_ip_to_abuseipdb() {
    local response
    response=$(curl --fail -s 'https://api.abuseipdb.com/api/v2/report' \
        -H 'Accept: application/json' \
        -H "Key: ${APIKEY}" \
        --data-urlencode "comment=${COMMENT}" \
        --data-urlencode "ip=${IP}" \
        --data "categories=${CATEGORIES}" 2>&1)

    if [[ $? -ne 0 ]]; then
        log_message "ERROR: API failure. Response: ${response} for IP: ${IP}"
    else
        log_message "SUCCESS: Reported IP ${IP} to AbuseIPDB."
    fi
}

check_ip_in_db() {
    local ip=$1 result
    result=$(sqlite3 "file:${SQLITE_DB}?mode=ro" "
        ${SQLITE_PRAGMAS}
        SELECT 1 FROM banned_ips WHERE ip = '${ip}' LIMIT 1;"
    )

    if [[ $? -ne 0 ]]; then
        log_message "ERROR: AbuseIPDB database query failed while checking IP ${ip}. Response: ${result}"
        return 1
    fi

    if [[ -n "${result}" ]]; then
        return 0
    else
        return 1
    fi
}

insert_ip_to_db() {
    local ip=$1
    local bantime=$2
    sqlite3 "${SQLITE_DB}" "
        ${SQLITE_PRAGMAS}
        BEGIN IMMEDIATE;
        INSERT INTO banned_ips (ip, bantime)
        VALUES ('${ip}', ${bantime})
        ON CONFLICT(ip) DO UPDATE SET bantime=${bantime};
        COMMIT;
    "

    if [[ $? -ne 0 ]]; then
        log_message "ERROR: Failed to insert or update IP ${ip} in the AbuseIPDB database."
    fi
}

#######################################
# FUNCTIONS: (END)
#######################################

#######################################
# MAIN (START)
#######################################

(
    is_found_local=0
    shouldBanIP=1

    if check_ip_in_db $IP; then
        is_found_local=1
        if check_ip_in_abuseipdb; then
            log_message "INFO: IP ${IP} has already been reported and remains on AbuseIPDB."
            shouldBanIP=0
        else
            log_message "INFO: IP ${IP} has already been reported but is no longer listed on AbuseIPDB."
            shouldBanIP=1
        fi
    else
        shouldBanIP=1
    fi

    if [[ "${shouldBanIP}" -eq 1 ]]; then
        if [[ "${is_found_local}" -eq 0 ]]; then
            insert_ip_to_db $IP $BANTIME
        fi
        report_ip_to_abuseipdb
    fi
) >> "${LOG_FILE}" 2>&1 &

#######################################
# MAIN (END)
#######################################

#######################################
# ACTIONBAN: (END)
#######################################

exit 0
