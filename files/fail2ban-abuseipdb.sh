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

log_message() {
    local message="$1"
    echo "$(date +"%Y-%m-%d %H:%M:%S") - ${message}" >> "${LOG_FILE}"
}

LOCK_INIT="/tmp/abuseipdb_actionstart_init.lock"
LOCK_BAN="/tmp/abuseipdb_actionstart_ban.lock"
LOCK_DONE="/tmp/abuseipdb_actionstart_done.lock"

remove_lock() {
    [[ -f "${LOCK_BAN}" ]] && rm -f "${LOCK_BAN}"
}

create_lock() {
    [[ ! -f "${LOCK_BAN}" ]] && touch "${LOCK_BAN}"
}

SQLITE_NON_PERSISTENT_PRAGMAS="PRAGMA synchronous=NORMAL; \
PRAGMA locking_mode=NORMAL; \
PRAGMA busy_timeout=10000;"

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
#   'LOCK_BAN' mechanism.
# - Use 'LOCK_INIT' and 'LOCK_DONE' to
#   manage concurrent calls on restarts.
########################################

if [[ "$1" == "--actionstart" ]]; then
(
    flock -n 200 || {
        [[ -f "${LOG_FILE}" ]] && log_message "WARNING: Another initialization is already running. Exiting."
        exit 0
    }

    if [[ -f "${LOCK_DONE}" ]]; then
        log_message "INFO: Initialization already completed. Skipping further checks."
        exit 0
    fi

    trap 'if [[ $? -ne 0 ]]; then create_lock; else remove_lock; fi' EXIT

    SQLITE_DIR=$(dirname "${SQLITE_DB}")
    if [[ ! -d "${SQLITE_DIR}" ]]; then
        mkdir -p "${SQLITE_DIR}" || exit 1
    fi

    LOG_DIR=$(dirname "${LOG_FILE}")
    if [[ ! -d "${LOG_DIR}" ]]; then
        mkdir -p "${LOG_DIR}" || exit 1
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
        log_message "INFO: AbuseIPDB database not found. Initializing..."
        sqlite3 "${SQLITE_DB}" "
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS banned_ips (
                ip TEXT PRIMARY KEY,
                bantime INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_ip ON banned_ips(ip);
        " &>/dev/null
        log_message "INFO: AbuseIPDB database is initialized!"
    fi

    table=$(sqlite3 "${SQLITE_DB}" "SELECT name FROM sqlite_master WHERE type='table' AND name='banned_ips';")
    if ! [[ -n "${table}" ]]; then
        log_message "ERROR: AbuseIPDB database initialization failed."
        exit 1
    fi

    touch "${LOCK_DONE}" || exit 1
    log_message "SUCCESS: All (actionstart) checks completed!"
    exit 0

) 200>"${LOCK_INIT}"
    exit 0
fi

#######################################
# ACTIONSTART: (END)
#######################################

#######################################
# ACTIONBAN: (START)
#######################################

#######################################
# 1) Fail2Ban restart handling &
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
#   on the local AbuseIPDB SQLite db,
#   even after restarts.
#######################################

#######################################
# 2) Prevent 'actionban' if
# 'actionstart' fails.
#
# - If 'actionstart' fails, block
#   'actionban' to prevent issues from
#   missing dependencies or permission
#   errors.
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

if [[ "${BYPASS_FAIL2BAN}" -eq 0 && "${RESTORED}" -eq 1 ]]; then
    log_message "INFO: (RESTART) IP ${IP} was already reported in the previous Fail2Ban session."
    exit 0
fi

if [[ -f "${LOCK_BAN}" ]]; then
    [[ -f "${LOG_FILE}" ]] && log_message "ERROR: Initialization failed! (actionstart). Reporting for IP ${IP} is blocked."
    exit 1
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
    if ! response=$(curl -sS -w "${delimiter}%{http_code}" -G "https://api.abuseipdb.com/api/v2/check" \
        --data-urlencode "ipAddress=${IP}" \
        -H "Key: ${APIKEY}" \
        -H "Accept: application/json" 2>&1); then
        log_message "ERROR: curl failed. Response: ${response}"
        return 2
    fi

    http_status="${response##*${delimiter}}"
    body="${response%"${delimiter}${http_status}"}"


    if [[ ! "${http_status}" =~ ^[0-9]+$ ]]; then
        log_message "ERROR: Invalid HTTP status in Response: ${response}"
        return 2
    fi

    if [[ "${http_status}" -ne 200 ]]; then
        if [[ "${http_status}" -eq 429 ]]; then
            log_message "ERROR: Rate limited (HTTP 429). Response: ${body}"
        else
            log_message "ERROR: HTTP ${http_status}. Response: ${body}"
        fi
        return 2
    fi

    total_reports=$(jq -r '.data.totalReports // 0' <<< "${body}")
    if (( total_reports > 0 )); then
        return 0
    fi
    return 1
}

convert_bantime() {
    local bantime=$1
    local time_value
    local time_unit

    if [[ "${bantime}" =~ ^[0-9]+$ ]]; then
        echo "${bantime}"
        return 0
    fi

    time_value="${bantime%"${bantime##*[0-9]}"}"
    time_unit="${bantime#${time_value}}"

    [[ -z "$time_unit" ]] && time_unit="s"

    case "$time_unit" in
        s) return $time_value ;;
        m) return $((time_value * 60)) ;;
        h) return $((time_value * 3600)) ;;
        d) return $((time_value * 86400)) ;;
        w) return $((time_value * 604800)) ;;
        y) return $((time_value * 31536000)) ;;
        *) return $time_value ;;
    esac
}

report_ip_to_abuseipdb() {
    local response http_status body delimiter="HTTP_STATUS:"
    if ! response=$(curl -sS -w "${delimiter}%{http_code}" "https://api.abuseipdb.com/api/v2/report" \
        -H 'Accept: application/json' \
        -H "Key: ${APIKEY}" \
        --data-urlencode "comment=${COMMENT}" \
        --data-urlencode "ip=${IP}" \
        --data "categories=${CATEGORIES}" 2>&1); then
        log_message "ERROR: curl failed. Response: ${response}"
        return 1
    fi

    http_status="${response##*${delimiter}}"
    body="${response%"${delimiter}${http_status}"}"

    if [[ ! "${http_status}" =~ ^[0-9]+$ ]]; then
        log_message "ERROR: Invalid HTTP status in response: ${response}"
        return 1
    fi

    if [[ "${http_status}" -ne 200 ]]; then
        if [[ "${http_status}" -eq 429 ]]; then
            log_message "ERROR: Rate limited (HTTP 429). Response: ${body}"
        else
            log_message "ERROR: HTTP ${http_status}. Response: ${body}"
        fi
        return 1
    fi

    log_message "SUCCESS: Reported IP ${IP} to AbuseIPDB."
    return 0
}

check_ip_in_db() {
    local ip=$1 result
    ip="${ip%"${ip##*[![:space:]]}"}"
    ip="${ip#"${ip%%[^[:space:]]*}"}"
    ip="${ip//\'/}"
    ip="${ip//\"/}"

    sqlite3 "${SQLITE_DB}" "${SQLITE_NON_PERSISTENT_PRAGMAS}" &>/dev/null
    result=$(sqlite3 "${SQLITE_DB}" "SELECT EXISTS(SELECT 1 FROM banned_ips WHERE ip = '${ip}');")

    if [[ "${result}" -eq 1 ]]; then
        return 0
    elif [[ "${result}" -eq 0 ]]; then
        return 1
    else
        return 2
    fi
}

insert_ip_to_db() {
    local ip=$1 bantime=$2
    bantime=$(convert_bantime "${bantime}")

    bantime="${bantime%"${bantime##*[![:space:]]}"}"
    bantime="${bantime#"${bantime%%[^[:space:]]*}"}"
    bantime="${bantime//\'/}"
    bantime="${bantime//\"/}"

    ip="${ip%"${ip##*[![:space:]]}"}"
    ip="${ip#"${ip%%[^[:space:]]*}"}"
    ip="${ip//\'/}"
    ip="${ip//\"/}"

    sqlite3 "${SQLITE_DB}" "${SQLITE_NON_PERSISTENT_PRAGMAS}" &>/dev/null
    sqlite3 "${SQLITE_DB}" "
        BEGIN IMMEDIATE;
        INSERT INTO banned_ips (ip, bantime)
        VALUES ('${ip}', ${bantime})
        ON CONFLICT(ip) DO UPDATE SET bantime=${bantime};
        COMMIT;
    "

    # TO-DO: Better handle SQLite INSERT ops. exit statuses
    # $? -ne 0 | I think not the best approach here.
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    return 0
}

delete_ip_from_db() {
    local ip=$1
    ip="${ip%"${ip##*[![:space:]]}"}"
    ip="${ip#"${ip%%[^[:space:]]*}"}"
    ip="${ip//\'/}"
    ip="${ip//\"/}"

    sqlite3 "${SQLITE_DB}" "${SQLITE_NON_PERSISTENT_PRAGMAS}" &>/dev/null
    sqlite3 "${SQLITE_DB}" "
        BEGIN IMMEDIATE;
        DELETE FROM banned_ips WHERE ip='${ip}';
        COMMIT;
    "

    # TO-DO: Do we need to listen exit status DELETE
    # I don't think so for now.
    log_message "INFO: IP ${ip} deleted from the AbuseIPDB SQLite database."
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
            status=$?
            if [[ "${status}" -eq 1 ]]; then
                log_message "INFO: IP ${IP} has already been reported but is no longer listed on AbuseIPDB. Resubmitting..."
            else
                log_message "ERROR: Failed to check IP ${IP} in the AbuseIPDB API. Skipping report."
                exit 1
            fi
        fi
    else
        status=$?
        if [[ "${status}" -eq 2 ]]; then
            log_message "ERROR: Failed to check IP ${IP} in the local database. Skipping report."
            exit 1
        fi
    fi

    if [[ "${shouldBanIP}" -eq 1 ]]; then
        if [[ "${is_found_local}" -eq 0 ]]; then
            if ! insert_ip_to_db $IP $BANTIME; then
                log_message "ERROR: Failed to insert IP ${IP} into the local database. Skipping report."
                exit 1
            fi
        fi

        if ! report_ip_to_abuseipdb; then
            delete_ip_from_db $IP
        fi
    fi
) >> "${LOG_FILE}" 2>&1 &

#######################################
# MAIN (END)
#######################################

#######################################
# ACTIONBAN: (END)
#######################################

exit 0
