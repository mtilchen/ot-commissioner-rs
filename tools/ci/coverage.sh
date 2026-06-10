#!/usr/bin/env bash
set -euo pipefail

coverage_dir="${COVERAGE_DIR:-target/llvm-cov}"
summary_json="${coverage_dir}/coverage-summary.json"
lcov_file="${coverage_dir}/lcov.info"

line_threshold="${COVERAGE_FAIL_UNDER_LINES:-80}"
region_threshold="${COVERAGE_FAIL_UNDER_REGIONS:-80}"
function_threshold="${COVERAGE_FAIL_UNDER_FUNCTIONS:-75}"

mkdir -p "${coverage_dir}"

cargo llvm-cov clean --workspace
cargo llvm-cov \
  --workspace \
  --all-features \
  --all-targets \
  --summary-only \
  --json \
  --output-path "${summary_json}" \
  --fail-under-lines "${line_threshold}" \
  --fail-under-regions "${region_threshold}" \
  --fail-under-functions "${function_threshold}"

cargo llvm-cov report --lcov --output-path "${lcov_file}"
cargo llvm-cov report --html --output-dir "${coverage_dir}"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  lines="$(jq -r '.data[0].totals.lines.percent' "${summary_json}")"
  regions="$(jq -r '.data[0].totals.regions.percent' "${summary_json}")"
  functions="$(jq -r '.data[0].totals.functions.percent' "${summary_json}")"
  covered_lines="$(jq -r '.data[0].totals.lines.covered' "${summary_json}")"
  total_lines="$(jq -r '.data[0].totals.lines.count' "${summary_json}")"
  covered_regions="$(jq -r '.data[0].totals.regions.covered' "${summary_json}")"
  total_regions="$(jq -r '.data[0].totals.regions.count' "${summary_json}")"
  covered_functions="$(jq -r '.data[0].totals.functions.covered' "${summary_json}")"
  total_functions="$(jq -r '.data[0].totals.functions.count' "${summary_json}")"

  {
    echo "## Coverage"
    echo
    echo "| Metric | Covered | Total | Percent | Threshold |"
    echo "| --- | ---: | ---: | ---: | ---: |"
    printf '| Lines | %s | %s | %.2f%% | %s%% |\n' \
      "${covered_lines}" "${total_lines}" "${lines}" "${line_threshold}"
    printf '| Regions | %s | %s | %.2f%% | %s%% |\n' \
      "${covered_regions}" "${total_regions}" "${regions}" "${region_threshold}"
    printf '| Functions | %s | %s | %.2f%% | %s%% |\n' \
      "${covered_functions}" "${total_functions}" "${functions}" "${function_threshold}"
    echo
    echo "Artifacts: \`${summary_json}\`, \`${lcov_file}\`, and \`${coverage_dir}/html/\`."
  } >> "${GITHUB_STEP_SUMMARY}"
fi
