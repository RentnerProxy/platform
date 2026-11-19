#!/usr/bin/env bash

# Sourced by the root production supervisor, which retains all child ownership.
readonly backup_control_directory=/run/rentnerproxy/backups
readonly backup_state_directory=/var/lib/rentnerproxy/backups
readonly backup_exporter=/opt/rentnerproxy/web/backup-export.js
backup_recovery_job=''
backup_maintenance_id=''
backup_caddy_pid=''

initialize_backup_lock() {
    local lock_file="$backup_state_directory/agent.lock"
    if [[ -e $backup_state_directory || -L $backup_state_directory ]]; then
        [[ -d $backup_state_directory && ! -L $backup_state_directory ]] \
            || fatal 'the backup state directory is not a real directory'
        [[ $(stat -c '%u:%a' -- "$backup_state_directory") == 0:700 ]] \
            || fatal 'the backup state directory has unsafe ownership or permissions'
    else
        install -d -m 0700 -o root -g root "$backup_state_directory"
    fi
    if [[ -e $lock_file || -L $lock_file ]]; then
        [[ -f $lock_file && ! -L $lock_file ]] \
            || fatal 'the backup agent lock is not a regular file'
        [[ $(stat -c '%u:%h' -- "$lock_file") == 0:1 ]] \
            || fatal 'the backup agent lock has unsafe ownership or links'
    fi
    # Preserve the inode: other namespaces may already hold its advisory lock.
    touch -- "$lock_file"
    chmod 0600 -- "$lock_file"
}

start_backup_agent() {
    local lock_file="$backup_state_directory/agent.lock"
    initialize_backup_lock
    if [[ -e $backup_control_directory || -L $backup_control_directory ]]; then
        [[ -d $backup_control_directory && ! -L $backup_control_directory ]] \
            || fatal 'the backup control directory is not a real directory'
        [[ $(stat -c '%u' -- "$backup_control_directory") == 0 ]] \
            || fatal 'the backup control directory is not root-owned'
    fi
    install -d -m 0750 -o root -g rentnerproxy "$backup_control_directory"
    # /run can survive a stop/start. Discard readiness evidence from the previous boot.
    rm -f -- "$backup_control_directory/agent.sock" "$backup_control_directory/restore-restarted.json"
    # No controller has started in this process namespace yet.
    rm -f -- "$backup_control_directory/controller-maintenance-request.json" \
        "$backup_control_directory/controller-maintenance-receipt.json" \
        "$backup_control_directory/controller-maintenance-owned.json"
    start_child backups flock --no-fork -n "$lock_file" \
        bun --no-env-file "$app_directory/backup-agent.js"
    wait_for_command 'backup agent' test -S "$backup_control_directory/agent.sock"
}

backup_write_result() {
    bun --no-env-file "$backup_exporter" --result "$1" "$2"
}

backup_quiesce_controller() {
    local id=$1 index controller_pid=''
    for index in "${!child_pids[@]}"; do
        [[ ${child_names[$index]} != controller ]] || controller_pid=${child_pids[$index]}
    done
    [[ -n $controller_pid && -z $backup_maintenance_id ]] \
        || fatal 'controller maintenance has no exclusive owned process'
    backup_maintenance_id=$id
    bun --no-env-file "$backup_exporter" --prepare-controller-maintenance "$id" "$controller_pid" \
        || fatal 'controller maintenance could not be prepared'
    backup_stop_consumer_phase controller || fatal 'controller could not quiesce safely'
    backup_caddy_pid=$(bun --no-env-file "$backup_exporter" --claim-controller-maintenance "$id") \
        || fatal 'controller maintenance handoff could not be confirmed'
    [[ $backup_caddy_pid =~ ^(0|[1-9][0-9]*)$ ]] || fatal 'invalid retained Caddy process'
}

backup_stop_retained_caddy() {
    [[ -n $backup_maintenance_id ]] || return 0
    bun --no-env-file "$backup_exporter" --finish-controller-maintenance "$backup_maintenance_id" \
        || return 1
    backup_caddy_pid=''
    backup_maintenance_id=''
}

backup_assert_state_children_running() {
    local index
    for index in "${!child_pids[@]}"; do
        case ${child_names[$index]} in backups|postgres|valkey) ;; *) continue ;; esac
        kill -0 "${child_pids[$index]}" 2>/dev/null \
            || fatal "${child_names[$index]} stopped during backup maintenance"
    done
}

backup_stop_consumer_phase() {
    local phase=$1 index pid status failed=false
    local -a stopping=() targets=() critical=()
    for index in "${!child_pids[@]}"; do
        case $phase:${child_names[$index]} in
            apps:app-manager|application:web|application:controller|controller:controller|web:web|crowdsec:crowdsec-supervisor)
                stopping+=("$index")
                targets+=("${child_pids[$index]}")
                ;;
            *:backups|*:postgres|*:valkey) critical+=("${child_pids[$index]}") ;;
        esac
    done
    appliance_drain "$phase" "${targets[@]}" -- "${critical[@]}" || return 1
    for index in "${stopping[@]}"; do
        pid=${child_pids[$index]}
        if wait "$pid"; then
            :
        else
            status=$?
            log "${child_names[$index]} exited with status $status during backup drain"
            failed=true
        fi
        unset "child_pids[$index]" "child_names[$index]"
    done
    [[ $failed == false ]]
}

backup_assert_consumers_stopped() {
    local index valkey_pid='' caddy_pid=${backup_caddy_pid:-0} mode=${1:-all}
    for index in "${!child_pids[@]}"; do
        if [[ ${child_names[$index]} == valkey ]]; then valkey_pid=${child_pids[$index]}; fi
    done
    [[ -n $valkey_pid ]] || fatal 'backup maintenance has no owned Valkey process'
    if [[ $caddy_pid != 0 ]]; then
        bun --no-env-file "$backup_exporter" --assert-retained-caddy "$backup_maintenance_id" "$caddy_pid" \
            || fatal 'retained Caddy ownership changed during maintenance'
    fi
    appliance_supervision verify-backup "$mode" "$valkey_pid" "$caddy_pid" \
        || fatal 'backup maintenance cannot prove all writers stopped'
    if [[ $caddy_pid != 0 ]]; then
        bun --no-env-file "$backup_exporter" --assert-retained-caddy "$backup_maintenance_id" "$caddy_pid" \
            || fatal 'retained Caddy ownership changed during the writer scan'
    fi
    backup_assert_state_children_running
}

backup_run_exporter() {
    # Four-hour operation plus five minutes to settle owned children and publish a result.
    # Keep aligned with BACKUP_RUNTIME_POLICY.supervisorTimeoutSeconds.
    local id=$1 mode=${2:---run} index pid status=0 budget=14700s
    start_child backup-export timeout --signal=TERM --kill-after=5s "$budget" \
        bun --no-env-file "$backup_exporter" "$mode" "$id"
    # Consumer removal leaves sparse arrays; locate the new child by its role.
    for index in "${!child_pids[@]}"; do
        [[ ${child_names[$index]} == backup-export ]] && break
    done
    pid=${child_pids[$index]}
    while kill -0 "$pid" 2>/dev/null; do
        backup_assert_state_children_running
        sleep 0.2
    done
    wait "$pid" || status=$?
    unset "child_pids[$index]" "child_names[$index]"
    # A killed runtime cannot prove its detached capture commands were reaped.
    # End the appliance instead of restarting writers beside an orphaned capture.
    if ((status == 2 || status == 124 || status >= 128)); then
        fatal 'backup exporter could not prove safe completion'
    fi
    return "$status"
}

perform_managed_restore() {
    local id
    [[ ! -e $backup_control_directory/active.json && ! -L $backup_control_directory/active.json ]] \
        || fatal 'backup maintenance is already active'
    mv -T -- "$backup_control_directory/request.json" "$backup_control_directory/active.json"
    id=$(bun --no-env-file "$backup_exporter" --request-id) || fatal 'invalid restore maintenance request'
    log "starting managed restore maintenance ($id)"
    backup_recovery_job=$id
    # Web drains its workers and DB pool after the root progress fence appears.
    # It keeps serving authenticated maintenance status while state writers stop.
    backup_stop_consumer_phase apps || fatal 'apps could not quiesce safely for restore'
    backup_quiesce_controller "$id"
    backup_stop_consumer_phase crowdsec || fatal 'CrowdSec could not quiesce safely for restore'
    backup_assert_consumers_stopped preserve-web
    if ! backup_run_exporter "$id" --restore; then
        backup_write_result "$id" execution_failed
        fatal 'managed restore failed; restart or explicit recovery is required'
    fi
    backup_assert_state_children_running
    # The web process caches the application key and has closed its DB pool.
    backup_stop_consumer_phase web || fatal 'maintenance web could not stop safely'
    backup_stop_retained_caddy || fatal 'retained Caddy could not stop safely'
    backup_assert_consumers_stopped
    # Replacement restores private archive modes; recreate the appliance's shared
    # Caddy/CrowdSec layout before their readiness and maintenance web can resume.
    initialize_layout
    initialize_secrets
    rm -f -- "$crowdsec_control_directory/status.json"
    start_crowdsec_supervisor
    start_controller
    run_migrations
    start_web
    wait_for_web_readiness
    backup_write_result "$id" success
    start_app_manager
    backup_recovery_job=''
    log "managed restore maintenance completed ($id)"
}

perform_managed_backup() {
    local id outcome=success
    [[ ! -e $backup_control_directory/active.json && ! -L $backup_control_directory/active.json ]] \
        || fatal 'a backup maintenance request is already active'
    mv -T -- "$backup_control_directory/request.json" "$backup_control_directory/active.json"
    id=$(bun --no-env-file "$backup_exporter" --request-id) \
        || fatal 'invalid backup maintenance request'
    log "starting managed backup maintenance ($id)"
    # Preserve state services and CrowdSec while application consumers drain.
    # Drain web while its controller is still available, then leave only Caddy's
    # in-memory proxy running. Its live logs are excluded from the archive.
    backup_stop_consumer_phase apps || fatal 'apps could not quiesce safely for backup'
    backup_stop_consumer_phase web || fatal 'web could not quiesce safely for backup'
    backup_quiesce_controller "$id"
    # An in-flight cscli call has a 25s bound; the engine then gets 12s to stop.
    backup_stop_consumer_phase crowdsec \
        || fatal 'CrowdSec could not quiesce safely for backup'
    backup_assert_consumers_stopped
    if ! backup_run_exporter "$id"; then outcome=execution_failed; fi
    backup_assert_state_children_running

    backup_recovery_job=$id
    backup_stop_retained_caddy || fatal 'retained Caddy could not stop safely'
    backup_assert_consumers_stopped

    # The EXIT trap records recovery_failed before state services/agent stop.
    rm -f -- "$crowdsec_control_directory/status.json"
    start_crowdsec_supervisor
    start_controller
    start_web
    wait_for_web_readiness
    backup_write_result "$id" "$outcome"
    start_app_manager
    backup_recovery_job=''
    log "managed backup maintenance completed ($id, $outcome)"
}
