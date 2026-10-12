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
#   ${10} MAX_WORKERS  - Required (User defined). Must be defined in 'action.d/abuseipdb.local'.   | Max concurrent AbuseIPDB API workers (default: 10)
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

MAX_WORKERS="${10:-10}"
if ! [[ "${MAX_WORKERS}" =~ ^[1-9][0-9]*$ ]]; then
    MAX_WORKERS=10
fi

log_message() {
    local message="$1"
    printf '%s - %s\n' "$(date +"%Y-%m-%d %H:%M:%S")" "${message}" >> "${LOG_FILE}"
}

RUNTIME_DIR="/run/fail2ban"
LOCK_INIT="${RUNTIME_DIR}/abuseipdb_init.lock"
LOCK_BAN="${RUNTIME_DIR}/abuseipdb_ban.lock"
LOCK_DONE="${RUNTIME_DIR}/abuseipdb_done.lock"

remove_lock() {
    [[ -f "${LOCK_BAN}" ]] && rm -f "${LOCK_BAN}"
}

create_lock() {
    [[ ! -f "${LOCK_BAN}" ]] && touch "${LOCK_BAN}"
}

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
    mkdir -p "${RUNTIME_DIR}" || exit 1
(
    flock -n 200 || {
        [[ -f "${LOG_FILE}" ]] && log_message "WARNING: Another initialization is already running. Exiting."
        exit 0
    }

    if [[ -f "${LOCK_DONE}" ]]; then
        db_ok=0
        if [[ -f "${SQLITE_DB}" ]]; then
            if sqlite3 "${SQLITE_DB}" \
                "PRAGMA integrity_check; SELECT name FROM sqlite_master WHERE type='table' AND name='banned_ips';" \
                2>/dev/null | grep -q "banned_ips"; then
                # Also verify schema completeness so a stale LOCK_DONE from a
                # pre-migration install doesn't skip the ALTER TABLE step.
                _col_present=$(sqlite3 "${SQLITE_DB}" \
                    "SELECT 1 FROM pragma_table_info('banned_ips') WHERE name='last_reported_at';" \
                    2>/dev/null)
                if [[ -n "${_col_present}" ]]; then
                    db_ok=1
                fi
            fi
        fi
        if [[ "${db_ok}" -eq 1 ]]; then
            log_message "INFO: Initialization already completed. DB healthy. Skipping."
            exit 0
        else
            log_message "WARNING: LOCK_DONE exists but DB is missing, corrupt, or needs schema migration. Re-initialising."
            rm -f "${LOCK_DONE}"
        fi
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

    log_message "INFO: Ensuring AbuseIPDB database and schema are present..."
    sqlite3 "${SQLITE_DB}" "
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS banned_ips (
            ip TEXT PRIMARY KEY,
            bantime INTEGER,
            last_reported_at INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_ip ON banned_ips(ip);
    " &>/dev/null || exit 1

    # Migrate existing installations: add last_reported_at if absent.
    _has_col=$(sqlite3 "${SQLITE_DB}" \
        "SELECT 1 FROM pragma_table_info('banned_ips') WHERE name='last_reported_at';" \
        2>/dev/null)
    if [[ -z "${_has_col}" ]]; then
        if ! sqlite3 "${SQLITE_DB}" \
            "ALTER TABLE banned_ips ADD COLUMN last_reported_at INTEGER DEFAULT 0;" \
            2>>"${LOG_FILE}"; then
            log_message "ERROR: Failed to migrate schema (add last_reported_at column)."
            exit 1
        fi
    fi

    log_message "INFO: AbuseIPDB database schema verified."

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

mkdir -p "${RUNTIME_DIR}" 2>/dev/null || true

#######################################
# EARLY CHECKS: (END)
#######################################

#######################################
# FUNCTIONS: (START)
#######################################

check_ip_in_abuseipdb() {
    local response http_status body total_reports delimiter="HTTP_STATUS:"
    if ! response=$(curl -sS --max-time 10 -w "${delimiter}%{http_code}" -G "https://api.abuseipdb.com/api/v2/check" \
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
    local bantime=$1 time_value time_unit
    if [[ "${bantime}" =~ ^[0-9]+$ ]]; then
        echo "${bantime}"
        return 0
    fi

    time_value="${bantime%"${bantime##*[0-9]}"}"
    time_unit="${bantime#${time_value}}"

    [[ -z "$time_unit" ]] && time_unit="s"

    case "${time_unit}" in
        s) echo "${time_value}" ;;
        m) echo "$((time_value * 60))" ;;
        h) echo "$((time_value * 3600))" ;;
        d) echo "$((time_value * 86400))" ;;
        w) echo "$((time_value * 604800))" ;;
        y) echo "$((time_value * 31536000))" ;;
        *) echo "${time_value}" ;;
    esac
}

report_ip_to_abuseipdb() {
    local response http_status body delimiter="HTTP_STATUS:"
    if ! response=$(curl -sS --max-time 10 -w "${delimiter}%{http_code}" "https://api.abuseipdb.com/api/v2/report" \
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
            if [[ "${body}" == *"15 minutes"* ]]; then
                log_message "INFO: IP ${IP} already reported within AbuseIPDB's 15-minute per-IP cooldown window. Treating as reported."
                return 0
            fi
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

result=$(sqlite3 "${SQLITE_DB}" <<SQL | tail -n 1
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA locking_mode=NORMAL;
PRAGMA busy_timeout=10000;
SELECT EXISTS(SELECT 1 FROM banned_ips WHERE ip = '${ip}');
SQL
)
    if [[ -z "${result}" ]]; then
        return 2
    elif [[ "${result}" -eq 1 ]]; then
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

sqlite3 "${SQLITE_DB}" <<SQL > /dev/null 2>&1
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA locking_mode=NORMAL;
PRAGMA busy_timeout=10000;
BEGIN IMMEDIATE;
INSERT INTO banned_ips (ip, bantime, last_reported_at)
VALUES ('${ip}', ${bantime}, strftime('%s','now'))
ON CONFLICT(ip) DO UPDATE SET bantime=${bantime}, last_reported_at=strftime('%s','now');
COMMIT;
SQL

    local rc=$?
    if [[ $rc -ne 0 ]]; then
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

sqlite3 "${SQLITE_DB}" <<SQL > /dev/null 2>&1
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA locking_mode=NORMAL;
PRAGMA busy_timeout=10000;
BEGIN IMMEDIATE;
DELETE FROM banned_ips WHERE ip='${ip}';
COMMIT;
SQL

    local rc=$?
    if [[ $rc -ne 0 ]]; then
        log_message "ERROR: Failed to delete IP ${ip} from the AbuseIPDB SQLite database."
        return 1
    fi

    log_message "INFO: IP ${ip} deleted from the AbuseIPDB SQLite database."
    return 0
}

is_in_report_cooldown() {
    local ip=$1 last_reported elapsed
    ip="${ip%"${ip##*[![:space:]]}"}"
    ip="${ip#"${ip%%[^[:space:]]*}"}"
    ip="${ip//\'/}"
    ip="${ip//\"/}"

last_reported=$(sqlite3 "${SQLITE_DB}" <<SQL | tail -n 1
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA locking_mode=NORMAL;
PRAGMA busy_timeout=10000;
SELECT COALESCE((SELECT last_reported_at FROM banned_ips WHERE ip='${ip}'), 0);
SQL
)
    # Empty = IP not in DB = never reported by this instance = not in cooldown
    if [[ -z "${last_reported}" || ! "${last_reported}" =~ ^[0-9]+$ || "${last_reported}" -eq 0 ]]; then
        return 1
    fi

    elapsed=$(( $(date +%s) - last_reported ))
    if [[ ${elapsed} -lt 0 ]]; then
        log_message "WARNING: last_reported_at for IP ${ip} is in the future (clock skew or corrupted data). Ignoring cooldown."
        return 1
    fi

    # within 15-minute AbuseIPDB per-IP cooldown
    if [[ ${elapsed} -lt 900 ]]; then
        return 0
    fi

    # cooldown expired, safe to report
    return 1
}

#######################################
# FUNCTIONS: (END)
#######################################

#######################################
# MAIN (START)
#######################################

(
    _init_wait=0
    while [[ ! -f "${LOCK_DONE}" && ! -f "${LOCK_BAN}" ]]; do
        if [[ ${_init_wait} -ge 60 ]]; then
            log_message "ERROR: Timed out waiting for actionstart init (60s) for IP ${IP}. Skipping."
            exit 1
        fi
        sleep 1
        (( _init_wait++ ))
    done

    if [[ -f "${LOCK_BAN}" ]]; then
        log_message "ERROR: Initialization failed! (actionstart). Reporting for IP ${IP} is blocked."
        exit 1
    fi

    # Per-IP dedup lock
    _safe_ip="${IP//[^a-zA-Z0-9._-]/_}"
    _ip_lock="${RUNTIME_DIR}/abuseipdb_${_safe_ip}.lock"
    exec 9>"${_ip_lock}"
    if ! flock -n 9; then
        log_message "INFO: IP ${IP} is already being processed by another worker. Skipping duplicate."
        exit 0
    fi

    # Remove lock file on exit
    trap 'rm -f "${_ip_lock}"' EXIT

    # Worker pool semaphore
    _slot_acquired=0
    _slot_wait_start=$(date +%s)

    while [[ ${_slot_acquired} -eq 0 ]]; do
        for (( _slot=1; _slot<=MAX_WORKERS; _slot++ )); do
            exec 8>"${RUNTIME_DIR}/abuseipdb_worker_${_slot}.lock"
            if flock -n 8; then
                _slot_acquired=1
                break 2
            fi
        done
        sleep 1
    done

    _slot_wait_elapsed=$(( $(date +%s) - _slot_wait_start ))
    if [[ ${_slot_wait_elapsed} -ge 30 ]]; then
        log_message "WARNING: IP ${IP} acquired worker slot ${_slot} after waiting ${_slot_wait_elapsed}s — pool may be saturated, consider raising MAX_WORKERS."
    elif [[ ${_slot_wait_elapsed} -gt 0 ]]; then
        log_message "INFO: IP ${IP} acquired worker slot ${_slot} after waiting ${_slot_wait_elapsed}s."
    else
        log_message "INFO: IP ${IP} acquired worker slot ${_slot} immediately."
    fi

    is_found_local=0
    shouldBanIP=1

    if check_ip_in_db "${IP}"; then
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
        if is_in_report_cooldown "${IP}"; then
            log_message "INFO: IP ${IP} is within the AbuseIPDB 15-minute per-IP report cooldown. Skipping."
            exit 0
        fi

        if [[ "${is_found_local}" -eq 0 ]]; then
            if ! insert_ip_to_db "${IP}" "${BANTIME}"; then
                log_message "ERROR: Failed to insert IP ${IP} into the local database. Skipping report."
                exit 1
            fi
        fi

        if ! report_ip_to_abuseipdb; then
            delete_ip_from_db "${IP}"
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
