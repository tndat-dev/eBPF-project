import unittest

from sentinel_pulse.capacity_contract import resolve


class CapacityContractTests(unittest.TestCase):
    def marker(self, minimum=0, maximum=85):
        return {"minimum_root_available_bytes": minimum, "maximum_root_used_percent": maximum}

    def test_zero_disables_fixed_byte_floor_not_percentage_guard(self):
        self.assertEqual(resolve(self.marker()), (0, 85))

    def test_old_run_keeps_registered_64_gib(self):
        self.assertEqual(resolve(self.marker(68719476736)), (68719476736, 85))

    def test_matching_explicit_overrides_are_allowed(self):
        self.assertEqual(resolve(self.marker(), "0", "85"), (0, 85))

    def test_cannot_weaken_or_change_registered_contract(self):
        for minimum, maximum in (("0", None), (None, "90"), ("34359738368", "85")):
            with self.subTest(minimum=minimum, maximum=maximum):
                with self.assertRaisesRegex(ValueError, "differs"):
                    resolve(self.marker(68719476736), minimum, maximum)

    def test_invalid_values_are_rejected(self):
        for minimum, maximum in ((-1, 85), (0, 0), (0, 100), (False, 85), (0, 85.0)):
            with self.subTest(minimum=minimum, maximum=maximum):
                with self.assertRaises(ValueError):
                    resolve(self.marker(minimum, maximum))

    def test_incomplete_or_absent_contract_is_rejected(self):
        for marker in ({}, {"minimum_root_available_bytes": 0}):
            with self.assertRaises(ValueError):
                resolve(marker)

    def test_invalid_environment_override_is_rejected(self):
        for override in ("", "-1", "NaN", "0.0", "\u0660"):
            with self.assertRaises(ValueError):
                resolve(self.marker(), override)


if __name__ == "__main__":
    unittest.main()
