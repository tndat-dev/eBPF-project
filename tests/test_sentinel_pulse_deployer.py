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
        self.assertNotIn("sentinel-detector.service", installer)
        self.assertIn("User=sentinel-pulse-detector", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("Nice=0", unit)
        self.assertIn("CPUWeight=200", unit)
        self.assertIn("CPUQuota=200%", unit)
        self.assertIn("MemoryHigh=768M", unit)
        self.assertIn("MemoryMax=1G", unit)
        self.assertNotIn("Nice=5", unit)
        self.assertIn("--alerts ${PULSE_ALERTS}", unit)
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

    def test_loader_drops_sigterm_short_window_before_snapshot(self):
        source = (
            ROOT / "sentinel_pulse" / "ebpf" / "pulse_counter_loader.c"
        ).read_text()
        sleep = source.index("usleep(interval_ms * 1000U);")
        exit_check = source.index("if (exiting)", sleep)
        refresh = source.index("refresh_targets(cgroups_fd", exit_check)
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
        self.assertNotIn("systemctl enable", runner)

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
