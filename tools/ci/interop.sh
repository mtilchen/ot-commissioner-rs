#!/usr/bin/env bash
#
# Live interop gate: commission a real OpenThread border agent.
#
# Builds OpenThread at a pinned ref (a posix ot-daemon border router driven by
# a simulated RCP over forkpty — the same arrangement the C++ ot-commissioner
# integration suite uses), forms a Thread network with fixed test vectors,
# then runs tests/interop_openthread.rs against the daemon's border agent on
# loopback. Requires Linux with passwordless sudo (ot-daemon needs a tun
# device); intended for CI but runnable on any Linux box.
#
# Env overrides:
#   OT_INTEROP_OPENTHREAD_REF  git ref of openthread/openthread to test against
#   OT_INTEROP_RUNTIME_DIR     scratch directory (default /tmp/ot-rs-interop)

set -euo pipefail

openthread_ref="${OT_INTEROP_OPENTHREAD_REF:-v2026.06.0}"
runtime_dir="${OT_INTEROP_RUNTIME_DIR:-/tmp/ot-rs-interop}"
openthread_dir="${runtime_dir}/openthread"
daemon_log="${runtime_dir}/ot-daemon.log"

# Fixed, non-secret network parameters: the test vectors from the C++
# ot-commissioner integration suite (tests/integration/common.sh).
readonly NETWORK_NAME=openthread-test
readonly CHANNEL=19
readonly CHANNEL_MASK=0x07fff800
readonly PANID=0xface
readonly XPANID=dead00beef00cafe
readonly NETWORK_KEY=00112233445566778899aabbccddeeff
readonly PSKC=3aa55f91ca47d1e4e71a08cb35e91591
readonly MESH_LOCAL_PREFIX="fd00:db8::"
readonly SECURITY_POLICY=(672 onrc)

ot_daemon="${openthread_dir}/build/posix/src/posix/ot-daemon"
ot_ctl="${openthread_dir}/build/posix/src/posix/ot-ctl"
ot_rcp="${openthread_dir}/build/simulation/examples/apps/ncp/ot-rcp"

die() {
    echo "*** ERROR: $*" >&2
    exit 1
}

ctl() {
    sudo timeout -k 5 10 "${ot_ctl}" "$@"
}

# Polls a command until it succeeds, failing after the given number of
# one-second attempts.
wait_for() {
    local description=$1 attempts=$2
    shift 2
    for _ in $(seq 1 "${attempts}"); do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    die "timed out waiting for ${description}"
}

build_openthread() {
    if [[ -x "${ot_daemon}" && -x "${ot_rcp}" ]]; then
        echo "Using cached OpenThread build at ${openthread_dir}"
        return
    fi
    rm -rf "${openthread_dir}"
    git clone --depth 1 --branch "${openthread_ref}" \
        https://github.com/openthread/openthread.git "${openthread_dir}"
    cd "${openthread_dir}"
    # The simulated RCP that stands in for an 802.15.4 radio.
    OT_CMAKE_NINJA_TARGET="ot-rcp" \
        ./script/cmake-build simulation -DOT_FTD=OFF -DOT_MTD=OFF \
        -DOT_APP_CLI=OFF -DOT_APP_NCP=OFF -DBUILD_TESTING=OFF
    # The posix border router; OT_PLATFORM_UDP puts the border agent on a
    # real host UDP socket so the commissioner can reach it over loopback.
    OT_CMAKE_NINJA_TARGET="ot-daemon ot-ctl" \
        ./script/cmake-build posix -DOT_DAEMON=ON -DOT_PLATFORM_NETIF=ON \
        -DOT_PLATFORM_UDP=ON -DBUILD_TESTING=OFF
    cd -
}

start_daemon() {
    sudo rm -rf "${runtime_dir}/daemon-settings"
    mkdir -p "${runtime_dir}/daemon-settings"
    (
        cd "${runtime_dir}/daemon-settings"
        sudo "${ot_daemon}" -I wpan0 -d4 \
            "spinel+hdlc+uart://${ot_rcp}?forkpty-arg=1" \
            >"${daemon_log}" 2>&1 &
    )
    wait_for "ot-daemon to accept commands" 30 sudo "${ot_ctl}" state
}

stop_daemon() {
    sudo killall ot-daemon 2>/dev/null || true
}

form_network() {
    ctl dataset clear
    ctl dataset activetimestamp 1
    ctl dataset channel "${CHANNEL}"
    ctl dataset channelmask "${CHANNEL_MASK}"
    ctl dataset extpanid "${XPANID}"
    ctl dataset meshlocalprefix "${MESH_LOCAL_PREFIX}"
    ctl dataset networkkey "${NETWORK_KEY}"
    ctl dataset networkname "${NETWORK_NAME}"
    ctl dataset panid "${PANID}"
    ctl dataset pskc "${PSKC}"
    ctl dataset securitypolicy "${SECURITY_POLICY[@]}"
    ctl dataset commit active
    ctl ifconfig up
    ctl thread start
    wait_for "the node to become leader" 60 \
        bash -c "sudo '${ot_ctl}' state | grep -q leader"
}

run_interop_test() {
    local ba_port dataset_hex
    ba_port="$(ctl ba port | grep -o '[0-9]\+' | head -1)"
    [[ -n "${ba_port}" ]] || die "could not read the border agent port"
    dataset_hex="$(ctl dataset active -x | grep -o '[0-9a-fA-F]\{16,\}' | head -1)"
    [[ -n "${dataset_hex}" ]] || die "could not read the active dataset"

    echo "Border agent on port ${ba_port}; commissioning..."
    OT_COMMISSIONER_INTEROP_BORDER_AGENT="[::1]:${ba_port}" \
        OT_COMMISSIONER_INTEROP_DATASET_HEX="${dataset_hex}" \
        cargo test --test interop_openthread --all-features -- --ignored --nocapture
}

write_summary() {
    local result=$1
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        {
            echo "## Interop"
            echo
            echo "| Peer | Role | Transport | Result |"
            echo "| --- | --- | --- | --- |"
            echo "| OpenThread \`${openthread_ref}\` (posix ot-daemon, simulated RCP) | border agent + leader | DTLS/EC-J-PAKE over UDP | ${result} |"
            echo
            echo "Covered: DTLS 1.2 + EC J-PAKE handshake (PSKc), COMM_PET, COMM_KA,"
            echo "MGMT_ACTIVE_GET (full dataset compare), MGMT_COMMISSIONER_GET via"
            echo "the UDP_TX/UDP_RX proxy to the leader ALOC, resign."
        } >>"${GITHUB_STEP_SUMMARY}"
    fi
}

cleanup() {
    local exit_code=$?
    stop_daemon
    if [[ ${exit_code} -ne 0 ]]; then
        write_summary "❌ failed"
        echo "=== ot-daemon log (tail) ==="
        sudo tail -50 "${daemon_log}" 2>/dev/null || true
    fi
    exit "${exit_code}"
}

main() {
    [[ "$(uname)" == "Linux" ]] || die "interop.sh needs Linux (ot-daemon uses a tun device)"
    mkdir -p "${runtime_dir}"
    trap cleanup EXIT

    build_openthread
    stop_daemon
    start_daemon
    form_network
    run_interop_test
    write_summary "✅ passed"
}

main "$@"
