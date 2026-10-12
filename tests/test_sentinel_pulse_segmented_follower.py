from sentinel_pulse.candidate_shadow import SegmentedJsonlFollower


def test_segmented_follower_reads_segments_in_order(tmp_path):
    root = tmp_path / "capture"
    first = root / "segments" / "s0001"
    second = root / "segments" / "s0002"
    first.mkdir(parents=True)
    second.mkdir()
    (first / "features.jsonl").write_text("first\n")
    (first / "TERMINAL.json").write_text("{}\n")
    (second / "features.jsonl").write_text("second\n")

    follower = SegmentedJsonlFollower(root, from_start=True, poll_seconds=0)
    try:
        assert follower.readline() == "first\n"
        assert follower.readline() == "second\n"
    finally:
        follower.close()


def test_live_restart_starts_at_end_of_latest_open_segment(tmp_path):
    root = tmp_path / "capture"
    closed = root / "segments" / "s0001"
    active = root / "segments" / "s0002"
    closed.mkdir(parents=True)
    active.mkdir()
    (closed / "features.jsonl").write_text("old-closed\n")
    (closed / "TERMINAL.json").write_text("{}\n")
    active_file = active / "features.jsonl"
    active_file.write_text("stale-backlog\n")

    follower = SegmentedJsonlFollower(root, poll_seconds=0)
    assert follower._open_next()
    try:
        with active_file.open("a") as stream:
            stream.write("live\n")
        assert follower.readline() == "live\n"
    finally:
        follower.close()


def test_segmented_follower_waits_for_future_segments_without_replaying(tmp_path):
    root = tmp_path / "capture"
    segment = root / "segments" / "s0007"
    segment.mkdir(parents=True)
    path = segment / "features.jsonl"
    path.write_text("stale\n")
    follower = SegmentedJsonlFollower(root, poll_seconds=0)
    assert follower._open_next()
    try:
        assert follower.current_number == 7
        assert not follower._open_next()
    finally:
        follower.close()
