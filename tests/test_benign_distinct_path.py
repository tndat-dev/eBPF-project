from sentinel_pulse.attack.cluster import (BENIGN_BASENAME, CONTROLLER_BINARY_PATHS, DEFAULT_BINARY_IN_CONTAINER,
                                           benign_path_for)
from sentinel_pulse.attack.preview_target import ALLOWED_PATHS, ATTACK_PATHS


def test_every_attack_path_has_an_allowlisted_benign_copy_beside_it():
    attack = set(CONTROLLER_BINARY_PATHS.values()) | {DEFAULT_BINARY_IN_CONTAINER}
    assert attack == ATTACK_PATHS
    for path in attack:
        benign = benign_path_for(path)
        assert benign in ALLOWED_PATHS and benign != path
        assert benign.rsplit('/', 1) == [path.rsplit('/', 1)[0], BENIGN_BASENAME]   # same directory, own name
