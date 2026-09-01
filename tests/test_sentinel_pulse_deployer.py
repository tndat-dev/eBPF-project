from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PulseDeployerTests(unittest.TestCase):
    def test_canary_deployer_never_rolls_remaining_workers_before_valid_report(self):
        script = (ROOT / "sentinel_pulse" / "deploy_canary_cluster.sh").read_text()
        validation = script.index('report.get("valid") is not True')
        rollout = script.index('for host in $REMAINING_HOSTS')
        self.assertLess(validation, rollout)
        self.assertIn("rsync -a --checksum", script)
        self.assertNotIn("--delete", script)
        self.assertIn("10.1.16.237", script)
        self.assertIn("10.1.16.238 10.1.16.239", script)
        self.assertIn("sentinel_pulse.validate_rollout", script)
        self.assertIn("rollout-validation.json", script)

    def test_collect_only_installer_does_not_install_training_stack(self):
        installer = (ROOT / "sentinel_pulse" / "install_node.sh").read_text()
        self.assertIn("requirements-collector.txt", installer)
        self.assertNotIn('-r "$PULSE_SOURCE/requirements.txt"', installer)
        self.assertGreaterEqual(
            installer.count("systemctl is-active --quiet sentinel-pulse-"), 2
        )
        self.assertIn("test -s /var/lib/sentinel-pulse/features.jsonl", installer)
        self.assertIn("systemctl stop sentinel-pulse-collector.service", installer)
        self.assertIn("systemctl restart sentinel-pulse-resolver.service", installer)
        self.assertIn("systemctl restart sentinel-pulse-collector.service", installer)

    def test_candidate_detector_is_checksum_gated_unprivileged_and_audit_only(self):
        installer = (
            ROOT / "sentinel_pulse" / "install_detector_candidate.sh"
        ).read_text()
        unit = (
            ROOT / "sentinel_pulse" / "systemd"
            / "sentinel-pulse-detector-candidate.service"
        ).read_text()
        self.assertIn("verify_model_bundle", installer)
        self.assertIn("PulseRuntime", installer)
        self.assertIn("mv -Tf", installer)
        self.assertIn("live decision model identity mismatch", installer)
        self.assertIn("live decision policy identity mismatch", installer)
        self.assertIn('systemctl reset-failed "$SERVICE"', installer)
        self.assertIn("FEATURE_SOURCE", installer)
        self.assertIn("ENABLE_INJECTION_TRACKING", installer)
        self.assertIn("PULSE_INJECTIONS", installer)
        self.assertIn("sentinel-pulse-readers", installer)
        self.assertIn("/var/lib/sentinel-pulse-500ms/runs/*/features.jsonl", installer)
        self.assertNotIn("sentinel-detector.service", installer)
        self.assertIn("User=sentinel-pulse-detector", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("Nice=0", unit)
        self.assertIn("CPUWeight=200", unit)
        self.assertIn("CPUQuota=200%", unit)
        self.assertIn("MemoryHigh=768M", unit)
        self.assertIn("MemoryMax=1G", unit)
        self.assertIn("ReadOnlyPaths=-/var/lib/sentinel-pulse-500ms", unit)
        self.assertNotIn("Nice=5", unit)
        self.assertIn("--alerts ${PULSE_ALERTS}", unit)
        self.assertIn("--injections ${PULSE_INJECTIONS}", unit)
        self.assertIn("--decision-policy ${PULSE_DECISION_POLICY}", unit)
        self.assertIn("--run-id ${PULSE_RUN_ID}", unit)
        self.assertNotIn("responder", unit.lower())
        detector = (ROOT / "sentinel_pulse" / "detect.py").read_text()
        self.assertIn('if __name__ == "__main__":\n    main()', detector)

    def test_resolver_owns_and_preserves_shared_runtime_directory(self):
        resolver = (
            ROOT / "sentinel_pulse" / "systemd" / "sentinel-pulse-resolver.service"
        ).read_text()
        collector = (
            ROOT / "sentinel_pulse" / "systemd" / "sentinel-pulse-collector.service"
        ).read_text()
        self.assertIn("RuntimeDirectory=sentinel-pulse", resolver)
        self.assertIn("RuntimeDirectoryPreserve=yes", resolver)
        self.assertNotIn("RuntimeDirectory=sentinel-pulse", collector)

    def test_bpf_tracked_syscalls_use_verifier_safe_constant_offsets(self):
        source = (
            ROOT / "sentinel_pulse" / "ebpf" / "pulse_counter.bpf.c"
        ).read_text()
        self.assertIn("static __always_inline void increment_tracked", source)
        self.assertIn("increment_tracked(counters, syscall_id);", source)
        self.assertIn("case 435: counters->tracked[28]++; break;", source)
        self.assertNotIn("tracked[slot]", source)

    def test_smoke_evaluator_runs_from_installed_package_parent(self):
        script = (ROOT / "sentinel_pulse" / "smoke_node.sh").read_text()
        self.assertIn("cd /opt/sentinel-pulse", script)
        self.assertIn("-m sentinel_pulse.smoke_collect", script)

    def test_loader_retries_torn_per_cpu_snapshots_and_exports_exhaustion(self):
        source = (
            ROOT / "sentinel_pulse" / "ebpf" / "pulse_counter_loader.c"
        ).read_text()
        self.assertIn("PULSE_SNAPSHOT_RETRIES 8", source)
        self.assertIn("per_cpu_snapshot_consistent", source)
        self.assertIn("snapshot_consistency_retry_exhausted", source)

    def test_500ms_experiment_is_isolated_collect_only_and_not_enabled(self):
        unit = (
            ROOT
            / "sentinel_pulse"
            / "systemd"
            / "sentinel-pulse-collector-500ms-experiment.service"
        ).read_text()
        installer = (
            ROOT / "sentinel_pulse" / "install_500ms_experiment.sh"
        ).read_text()
        finalizer = (
            ROOT / "sentinel_pulse" / "finalize_500ms_experiment.sh"
        ).read_text()
        metrics = (
            ROOT / "sentinel_pulse" / "record_500ms_metrics.sh"
        ).read_text()
        self.assertIn("--interval-ms 500", unit)
        self.assertIn("--rolling-windows 10", unit)
        self.assertIn("${PULSE_500MS_OUTPUT}", unit)
        self.assertIn("${PULSE_500MS_DURATION_SECONDS}s", unit)
        self.assertIn("Restart=no", unit)
        self.assertIn("ExecStopPost=/opt/sentinel-pulse/bin/record_500ms_metrics", unit)
        self.assertIn("Nice=0", unit)
        self.assertNotIn("sentinel_pulse.detect", unit)
        self.assertNotIn("systemctl enable", installer)
        self.assertIn('systemctl is-enabled "$SERVICE"', installer)
        self.assertIn("static|disabled|indirect|generated|transient", installer)
        self.assertIn("enabled|enabled-runtime|linked|linked-runtime|alias", installer)
        self.assertIn('"$RUN_DIR/START.json"', installer)
        self.assertIn("sentinel-pulse-500ms-start-v1", installer)
        self.assertIn("control-collector-start.systemd", installer)
        self.assertIn("record_500ms_metrics", installer)
        self.assertIn("--interval-min-seconds 0.35", finalizer)
        self.assertIn("--interval-max-seconds 0.80", finalizer)
        self.assertIn("cd /opt/sentinel-pulse", finalizer)
        self.assertIn("sentinel-pulse-500ms-final-v1", finalizer)
        self.assertIn('chmod 0444 "$RUN_DIR"/*', finalizer)
        self.assertIn("experiment-cgroup-final.txt", finalizer)
        self.assertIn("control-collector-at-experiment-end.systemd", metrics)
        self.assertIn("stopped_at_unix", metrics)

    def test_formal_500ms_soak_is_preregistered_and_never_promotes(self):
        script = (
            ROOT / "sentinel_pulse" / "start_500ms_normal_soak.sh"
        ).read_text()
        marker = script.index('SOAK_START.json')
        collector = script.index('install_500ms_experiment.sh')
        self.assertLess(marker, collector)
        self.assertIn('"automatic_promotion": False', script)
        self.assertIn('"blind_evaluation_started": False', script)
        self.assertIn("DURATION_SECONDS >= 86400", script)
        self.assertIn("10.1.16.237|k8s-worker1.local", script)
        self.assertIn("10.1.16.239|k8s-worker3.local", script)
        self.assertIn("10.1.16.238|k8s-worker4.local", script)
        self.assertIn("PULSE_FEATURES=$feature", script)
        self.assertIn("trap cleanup EXIT", script)
        self.assertIn("launch_failed_at", script)
        self.assertIn("systemctl stop sentinel-pulse-detector-candidate.service", script)
        self.assertIn("systemctl daemon-reload", script)
        self.assertIn("systemctl show sentinel-pulse-resolver -p Requires", script)
        self.assertIn("sentinel_pulse.storage_health", script)
        self.assertIn("REQUIRE_CONTROL_COLLECTOR=false", script)
        self.assertIn("! systemctl is-active --quiet sentinel-pulse-collector", script)
        self.assertNotIn("systemctl enable", script)

    def test_runtime_units_do_not_propagate_transient_dependency_restarts(self):
        unit_root = ROOT / "sentinel_pulse" / "systemd"
        resolver = (unit_root / "sentinel-pulse-resolver.service").read_text()
        collector = (unit_root / "sentinel-pulse-collector.service").read_text()
        experiment = (
            unit_root / "sentinel-pulse-collector-500ms-experiment.service"
        ).read_text()
        detector = (
            unit_root / "sentinel-pulse-detector-candidate.service"
        ).read_text()
        self.assertIn("Wants=containerd.service", resolver)
        self.assertNotIn("Requires=containerd.service", resolver)
        self.assertIn("Wants=sentinel-pulse-resolver.service", collector)
        self.assertNotIn("Requires=sentinel-pulse-resolver.service", collector)
        self.assertIn("Wants=sentinel-pulse-resolver.service", experiment)
        self.assertNotIn("Requires=sentinel-pulse-resolver.service", experiment)
        self.assertIn("StartLimitBurst=3", detector)
        self.assertIn("StartLimitIntervalSec=60", detector)

    def test_formal_soak_monitor_is_read_only_and_fail_closed(self):
        script = (
            ROOT / "sentinel_pulse" / "monitor_500ms_normal_soak.sh"
        ).read_text()
        self.assertIn("normal_alert_observed", script)
        self.assertIn("detector_restarted", script)
        self.assertIn("feature_source_mismatch", script)
        self.assertIn("duplicate_longhorn_disk_uuid", script)
        self.assertIn("colocated_longhorn_replicas", script)
        self.assertIn("legacy_control_collector_active", script)
        self.assertIn("READY_TO_FINALIZE", script)
        self.assertIn("eligible_finalize_after", script)
        self.assertNotIn("systemctl restart", script)
        self.assertNotIn("systemctl stop", script)
        self.assertNotIn("kubectl apply", script)

    def test_failed_soak_freezer_is_fail_closed_and_self_contained(self):
        script = (
            ROOT / "sentinel_pulse" / "freeze_failed_500ms_normal_soak.sh"
        ).read_text()
        self.assertIn("rejected_infrastructure_failure", script)
        self.assertIn('"normal_gate": False', script)
        self.assertIn('"training": False', script)
        self.assertIn('"tuning": False', script)
        self.assertIn('"blind_attack": False', script)
        self.assertIn("raw.tar.gz", script)
        self.assertIn("resume checkpoint", script)
        self.assertIn("RAW_SHA256SUMS", script)
        self.assertIn("ARCHIVE_COMPLETE", script)
        self.assertIn("! -name archive.log", script)
        self.assertIn("! -name '*.tmp'", script)
        self.assertNotIn("evaluate_normal", script)

    def test_candidate_lifecycle_is_resumable_fail_closed_and_non_promoting(self):
        script = (
            ROOT / "sentinel_pulse" / "run_500ms_candidate_lifecycle.sh"
        ).read_text()
        monitor = script.index("monitor_500ms_normal_soak.sh")
        finalizer = script.index("finalize_500ms_normal_soak.sh")
        blind = script.index("run_500ms_blind_campaign.sh")
        self.assertLess(monitor, finalizer)
        self.assertLess(finalizer, blind)
        self.assertIn("freeze_failed_500ms_normal_soak.sh", script)
        self.assertIn("NORMAL_PASS", script)
        self.assertIn("refusing automatic rerun", script)
        self.assertIn('"automatic_promotion": False', script)
        self.assertNotIn("kubectl apply", script)

    def test_dependency_restart_canary_reproduces_a2_trigger(self):
        script = (
            ROOT / "sentinel_pulse" / "run_dependency_restart_canary.sh"
        ).read_text()
        restart = script.index("systemctl restart containerd.service")
        active_after = script.index(
            "sentinel-pulse-collector-500ms-experiment", restart
        )
        self.assertLess(restart, active_after)
        self.assertIn("rows_after > rows_before", script)
        self.assertIn("cluster_healthy_after_restart", script)
        self.assertIn("SHA256SUMS", script)
        self.assertIn('"automatic_promotion": False', script)

    def test_lifecycle_service_is_reboot_resumable_and_secret_is_root_only(self):
        script = (
            ROOT / "sentinel_pulse" / "install_candidate_lifecycle_service.sh"
        ).read_text()
        self.assertIn("WantedBy=multi-user.target", script)
        self.assertIn("systemctl enable --now", script)
        self.assertIn("EnvironmentFile=", script)
        self.assertIn("chmod 0600", script)
        self.assertIn("Restart=no", script)
        self.assertIn("remote", script)
        self.assertNotIn("SSHPASS=1", script)

    def test_formal_soak_finalizer_freezes_all_nodes_before_evaluation(self):
        script = (
            ROOT / "sentinel_pulse" / "finalize_500ms_normal_soak.sh"
        ).read_text()
        detector_stop = script.index(
            "systemctl stop sentinel-pulse-detector-candidate.service"
        )
        collector_stop = script.index(
            "systemctl stop sentinel-pulse-collector-500ms-experiment.service"
        )
        evaluation = script.index("sentinel_pulse.evaluate_normal")
        self.assertLess(detector_stop, collector_stop)
        self.assertLess(collector_stop, evaluation)
        self.assertIn("FINALIZE_MARGIN_SECONDS", script)
        self.assertIn("--model-manifest", script)
        self.assertIn("expected_workload_gate", script)
        self.assertIn("automatic_promotion=false", script)
        self.assertNotIn("kubectl apply", script)

    def test_loader_drops_sigterm_short_window_before_snapshot(self):
        source = (
            ROOT / "sentinel_pulse" / "ebpf" / "pulse_counter_loader.c"
        ).read_text()
        sleep = source.index("usleep(interval_ms * 1000U);")
        exit_check = source.index("if (exiting)", sleep)
        refresh = source.index("refresh_targets_bounded(cgroups_fd", exit_check)
        self.assertLess(sleep, exit_check)
        self.assertLess(exit_check, refresh)

    def test_500ms_overhead_runner_is_counterbalanced_and_never_promotes(self):
        runner = (
            ROOT / "sentinel_pulse" / "run_500ms_overhead_ab.sh"
        ).read_text()
        self.assertIn("phases=(off on on off on off off on)", runner)
        self.assertIn("automatic_promotion", runner)
        self.assertIn("--max-failed-requests 0", runner)
        self.assertIn("endpoint_uid|$endpoint_ip|Running", runner)
        self.assertIn("sentinel-pulse-detector-candidate.service", runner)
        self.assertIn("aggregate_500ms_overhead", runner)
        self.assertIn("PULSE_500MS_AB_TREATMENT", runner)
        self.assertIn('TREATMENT == pipeline', runner)
        self.assertIn('status == "eligible_for_overhead_evaluation"', runner)
        self.assertIn("pipeline-overhead-contract-v1.json", runner)
        self.assertIn("sentinel-pulse-detector-candidate.service", runner)
        self.assertIn("wc -l < '$alert_path'", runner)
        self.assertIn("SOURCE_SHA256SUMS", runner)
        self.assertIn("--warmup-duration", runner)
        self.assertIn("verify_cluster campaign-start", runner)
        self.assertIn('verify_cluster "$phase_name-before"', runner)
        self.assertIn('verify_cluster "$phase_name-after"', runner)
        self.assertIn("volumes.longhorn.io", runner)
        self.assertIn("clusters.postgresql.cnpg.io", runner)
        self.assertIn('"node": sys.argv[12]', runner)
        self.assertNotIn('"node": "k8s-worker1.local"', runner)
        self.assertNotIn("systemctl enable", runner)

    def test_500ms_dataset_campaign_is_multinode_normal_only_and_never_promotes(self):
        runner = (
            ROOT / "sentinel_pulse" / "run_500ms_dataset_campaign.sh"
        ).read_text()
        self.assertIn("k8s-worker1.local k8s-worker3.local k8s-worker4.local", runner)
        self.assertIn("regimes=(steady toolmix burst recovery)", runner)
        self.assertIn('"normal_only": True', runner)
        self.assertIn('"automatic_model_training": False', runner)
        self.assertIn('"automatic_promotion": False', runner)
        self.assertIn("--interval-min-seconds 0.35", runner)
        self.assertIn("--interval-max-seconds 0.80", runner)
        self.assertIn("finalize_500ms_dataset", runner)
        self.assertIn("TRANSITION_GAP_SECONDS:-180", runner)
        self.assertIn('stage=%s\\n', runner)
        self.assertIn('$regime-rollout.log', runner)
        self.assertIn("for attempt in 1 2", runner)
        self.assertIn("HEALTH_FAILURE_LIMIT", runner)
        self.assertIn("health-warning-$timestamp.txt", runner)
        self.assertIn("collectors_started=true", runner)
        self.assertIn("PULSE_500MS_CAMPAIGN_MODE", runner)
        self.assertIn("PULSE_500MS_PILOT_ACK=nonformal", runner)
        self.assertIn('"nonformal_runtime_compatibility_pilot"', runner)
        self.assertIn('"source_clean": not git_status', runner)
        self.assertIn('"git_diff_sha256"', runner)
        self.assertIn("contract_reference", runner)
        self.assertIn('root / "sentinel_pulse/ebpf/pulse_counter_loader.c"', runner)
        self.assertIn('root / "sentinel_pulse/capture.py"', runner)
        self.assertIn('if [[ $CAMPAIGN_MODE == formal ]]', runner)
        self.assertIn('cd "$ROOT"', runner)
        self.assertNotIn("systemctl enable", runner)

    def test_loader_distinguishes_empty_allowlist_from_bpf_map_failure(self):
        source = (
            ROOT / "sentinel_pulse" / "ebpf" / "pulse_counter_loader.c"
        ).read_text()
        self.assertIn("if (targets < 0)", source)
        self.assertIn("failed to populate target cgroups", source)
        self.assertIn("if (targets == 0)", source)
        self.assertIn("no valid target cgroup", source)
        self.assertIn("PULSE_TARGET_REFRESH_RETRIES 5", source)
        self.assertIn("refresh_targets_bounded", source)
        self.assertIn("result != -ENOMEM && result != -EAGAIN", source)
        self.assertIn("target refresh attempt", source)

    def test_counter_allowlist_preallocates_a_bounded_capacity(self):
        source = (
            ROOT / "sentinel_pulse" / "ebpf" / "pulse_counter.bpf.c"
        ).read_text()
        allowlist = source.split("} pulse_cgroups SEC", 1)[0].rsplit("struct {", 1)[1]
        self.assertIn("BPF_MAP_TYPE_PERCPU_HASH", allowlist)
        self.assertIn("max_entries, 1024", allowlist)
        self.assertNotIn("BPF_F_NO_PREALLOC", allowlist)

    def test_pilot_postprocess_is_ordered_and_never_promotes(self):
        script = (
            ROOT / "sentinel_pulse" / "run_pilot_postprocess.sh"
        ).read_text()
        checksum = script.index("sha256sum -c")
        coverage = script.index("sentinel_pulse.audit_calibration_coverage")
        freeze = script.index("sentinel_pulse.freeze_training_contract")
        train = script.index("sentinel_pulse.train")
        benchmark = script.index("sentinel_pulse.benchmark_inference")
        self.assertLess(checksum, coverage)
        self.assertLess(coverage, freeze)
        self.assertLess(freeze, train)
        self.assertLess(train, benchmark)
        self.assertIn("automatic_model_training == false", script)
        self.assertIn("automatic_promotion == false", script)
        self.assertNotIn("install_detector_candidate", script)
        self.assertNotIn("kubectl apply", script)

    def test_live_canary_finalizer_is_bounded_and_never_promotes(self):
        script = (
            ROOT / "sentinel_pulse" / "finalize_live_canary.sh"
        ).read_text()
        self.assertIn("WAIT_TIMEOUT_SECONDS", script)
        self.assertIn("systemctl stop \"$DETECTOR\"", script)
        self.assertIn("systemctl disable \"$DETECTOR\"", script)
        self.assertIn('"accuracy_claim_allowed": False', script)
        self.assertIn('"automatic_promotion": False', script)
        self.assertIn("window_start_to_alert_seconds", script)
        self.assertIn("window_start_to_decision_seconds", script)
        self.assertIn('"node_name"', script)
        self.assertIn("EXPECTED_MODEL_SHA256", script)
        self.assertIn("EXPECTED_POLICY_SHA256", script)
        self.assertNotIn("install_detector_candidate", script)
        self.assertNotIn("kubectl apply", script)

    def test_formal_soak_requires_pressure_free_stable_cluster(self):
        starter = (
            ROOT / "sentinel_pulse" / "start_500ms_normal_soak.sh"
        ).read_text()
        monitor = (
            ROOT / "sentinel_pulse" / "monitor_500ms_normal_soak.sh"
        ).read_text()
        self.assertIn("wait_for_stable_cluster", starter)
        self.assertIn("--resource nodes", starter)
        self.assertIn("PREFLIGHT_STABILITY_SECONDS", starter)
        self.assertIn("longhorn_bad", starter)
        self.assertIn("cnpg_bad", starter)
        self.assertIn("MINIMUM_ROOT_AVAILABLE_BYTES", starter)
        self.assertIn("worker_capacity_snapshot", starter)
        self.assertIn("worker_maintenance_snapshot", starter)
        self.assertIn("unattended-upgrades.service", starter)
        self.assertIn("apt-daily-upgrade.timer", starter)
        self.assertIn("sentinel-pulse-semantic-soak-start-v7", starter)
        self.assertIn('"maintenance_window_guard"', starter)
        self.assertIn("SUSPEND_CONTROL_COLLECTOR", starter)
        self.assertIn('"control_collector_suspended_hosts"', starter)
        self.assertIn("systemctl start sentinel-pulse-collector.service", starter)
        self.assertIn("check_cluster_health", monitor)
        self.assertIn("check_worker_capacity", monitor)
        self.assertIn("check_worker_maintenance", monitor)
        self.assertIn("FAILURE_MAINTENANCE.txt", monitor)
        self.assertIn("package_maintenance_guard_lost", monitor)
        self.assertIn("insufficient_worker_capacity", monitor)
        self.assertIn("unhealthy_kubernetes_node", monitor)
        self.assertIn("FAILURE_NODES.json", monitor)

        finalizer = (
            ROOT / "sentinel_pulse" / "finalize_500ms_normal_soak.sh"
        ).read_text()
        failure_archive = (
            ROOT / "sentinel_pulse" / "freeze_failed_500ms_normal_soak.sh"
        ).read_text()
        for lifecycle_terminal in (finalizer, failure_archive):
            self.assertIn("CONTROL_COLLECTOR_RESTORED.json", lifecycle_terminal)
            self.assertIn(
                "systemctl start sentinel-pulse-collector.service",
                lifecycle_terminal,
            )

    def test_candidate_lifecycle_can_stop_before_opening_blind_evaluation(self):
        lifecycle = (
            ROOT / "sentinel_pulse" / "run_500ms_candidate_lifecycle.sh"
        ).read_text()
        interlock = lifecycle.index("if [[ $STOP_AFTER_NORMAL == true ]]")
        blind = lifecycle.index("phase normal_pass_blind_interlock_open")
        self.assertLess(interlock, blind)
        self.assertIn("phase lifecycle_complete_after_normal", lifecycle)
        self.assertIn(
            "[[ $STOP_AFTER_NORMAL == true || $STOP_AFTER_NORMAL == false ]]",
            lifecycle,
        )

    def test_capture_campaign_monitors_cluster_and_records_failure(self):
        script = (ROOT / "sentinel_pulse" / "run_capture_campaign.sh").read_text()
        self.assertIn("check_cluster_health", script)
        self.assertIn("ready_nodes=%s expected=6", script)
        self.assertIn("CAMPAIGN_ACTIVE", script)
        self.assertIn("CAMPAIGN_FAILED", script)
        self.assertIn("$regime-deployments.json", script)
        self.assertIn("HEALTH_FAILURE_LIMIT", script)
        self.assertIn("health-warning-$timestamp.txt", script)

    def test_node_finalizer_rotates_then_hashes_an_immutable_capture(self):
        script = (ROOT / "sentinel_pulse" / "finalize_capture_node.sh").read_text()
        self.assertIn('systemctl stop sentinel-pulse-collector.service', script)
        self.assertIn('mv "$ACTIVE_CAPTURE" "$FROZEN_CAPTURE"', script)
        self.assertIn('chmod 0444 "$FROZEN_CAPTURE"', script)
        self.assertIn('systemctl start sentinel-pulse-collector.service', script)
        self.assertIn('"capture_sha256": digest.hexdigest()', script)
        self.assertIn('date -u +%FT%TZ >"$MARKER"', script)

    def test_control_capture_rotation_is_bounded_and_experiment_safe(self):
        script = (
            ROOT / "sentinel_pulse" / "rotate_control_capture.sh"
        ).read_text()
        installer = (ROOT / "sentinel_pulse" / "install_node.sh").read_text()
        timer = (
            ROOT
            / "sentinel_pulse"
            / "systemd"
            / "sentinel-pulse-control-rotate.timer"
        ).read_text()
        self.assertIn("sentinel-pulse-collector-500ms-experiment.service", script)
        self.assertIn("sentinel-pulse-detector-candidate.service", script)
        self.assertIn('mv "$CAPTURE" "$archive"', script)
        self.assertIn('gzip -1 "$archive"', script)
        self.assertIn("uncompressed_sha256", script)
        self.assertIn("sentinel-pulse-control-rotate.timer", installer)
        self.assertIn("OnCalendar=", timer)

    def test_finalizer_is_persistent_and_config_is_immutable(self):
        arm = (ROOT / "sentinel_pulse" / "arm_capture_finalizer.sh").read_text()
        unit = (
            ROOT / "sentinel_pulse" / "systemd" / "sentinel-pulse-freeze@.service"
        ).read_text()
        self.assertIn("cmp -s", arm)
        self.assertIn("systemctl enable --now", arm)
        self.assertIn("Type=simple", unit)
        self.assertIn("EnvironmentFile=/etc/sentinel-pulse/campaigns/%i.env", unit)
        self.assertIn("Restart=on-failure", unit)


if __name__ == "__main__":
    unittest.main()
