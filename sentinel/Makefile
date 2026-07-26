.PHONY: test compile metrics
test:
	python3 -m pytest -q
compile:
	python3 -m compileall -q .
metrics:
	DURATION_SECONDS=$${DURATION_SECONDS:-300} ./benchmarks/collect_cluster_metrics.sh
