#!/usr/bin/env bash
# Run a few cheap queries against the live Criminal IP API through Steampipe
# and check that each one returns rows with the expected columns.
#
# Used by .github/workflows/live-api-check.yml. Expects `steampipe` on PATH,
# the plugin installed as local/criminalip in $STEAMPIPE_INSTALL_DIR, and
# CRIMINALIP_API_KEY in the environment. Costs about 6 API calls, run one
# after the other (Criminal IP allows one concurrent call per key).
#
# Never prints query results: criminalip_account comes from /v1/user/me, whose
# response includes the API key. Only row counts and column names are logged.
set -euo pipefail

: "${CRIMINALIP_API_KEY:?CRIMINALIP_API_KEY is not set}"
echo "::add-mask::${CRIMINALIP_API_KEY}"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT
failures=0

redact() {
    local text
    text="$(cat)"
    printf '%s\n' "${text//"${CRIMINALIP_API_KEY}"/***}"
}

# check NAME MIN_ROWS "col1 col2 ..." "notnull1 notnull2 ..." SQL
#   MIN_ROWS   the query must return at least this many rows
#   columns    must all appear in the result
#   notnull    must be non-null in the first row
check() {
    local name=$1 min_rows=$2 columns=$3 notnull=$4 sql=$5
    local out="${workdir}/${name}.json" err="${workdir}/${name}.err"

    echo "::group::${name}"
    if ! steampipe query --output json "${sql}" >"${out}" 2>"${err}"; then
        echo "::error title=Live API check: ${name}::query failed"
        redact <"${err}" | tail -n 20
        echo "::endgroup::"
        failures=$((failures + 1))
        return 0
    fi

    local problems
    problems="$(jq -r --argjson min "${min_rows}" --arg columns "${columns}" --arg notnull "${notnull}" '
        . as $r
        | [$r.columns[].name] as $have
        | ($r.rows | length) as $n
        | (if $n < $min then "expected at least \($min) row(s), got \($n)" else empty end),
          ($columns | split(" ")[] | select(length > 0) | select(IN($have[]) | not)
              | "missing column \(.)"),
          (if $n > 0 then
              ($notnull | split(" ")[] | select(length > 0) | select(. as $c | $r.rows[0][$c] == null)
                  | "column \(.) is null in the first row")
           else empty end)
        ' "${out}" 2>&1 || echo "could not parse the query output as JSON")"
    echo "rows: $(jq '.rows | length' "${out}" 2>/dev/null || echo '?')"
    echo "columns: $(jq -r '[.columns[].name] | join(", ")' "${out}" 2>/dev/null || echo '?')"
    if [[ -n "${problems}" ]]; then
        while IFS= read -r p; do
            echo "::error title=Live API check: ${name}::$(redact <<<"${p}")"
        done <<<"${problems}"
        failures=$((failures + 1))
    else
        echo "ok"
    fi
    echo "::endgroup::"
}

check account 1 \
    "email name account_type membership_date" \
    "email" \
    "select email, name, account_type, membership_date from criminalip_account"

check ip 1 \
    "ip score_inbound score_outbound country_code as_no is_malicious" \
    "ip score_inbound country_code" \
    "select ip, score_inbound, score_outbound, country_code, as_no, is_malicious from criminalip_ip where ip = '8.8.8.8'"

check banner_search 1 \
    "ip_address open_port_no service_name scan_dtime total_count" \
    "ip_address open_port_no total_count" \
    "select ip_address, open_port_no, service_name, scan_dtime, total_count from criminalip_banner_search where query = 'ip: 8.8.8.0/24' limit 5"

check domain_quick 1 \
    "domain found result type" \
    "domain found result" \
    "select domain, found, result, type from criminalip_domain_quick where domain = 'google.com'"

check exploit_search 1 \
    "edb_id title platform type cve_id total_count" \
    "edb_id title" \
    "select edb_id, title, platform, type, cve_id, total_count from criminalip_exploit_search where query = 'cve_id: CVE-2021-41773' limit 1"

if ((failures > 0)); then
    echo "::error title=Live API check::${failures} of 5 queries failed. The Criminal IP API may have changed; see the log above."
    exit 1
fi
echo "All live queries passed."
