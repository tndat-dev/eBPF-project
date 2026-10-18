import unittest
import subprocess
import sys



class PulseContractTests(unittest.TestCase):
    def test_package_import_does_not_eagerly_import_numpy(self):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sentinel_pulse,sys; "
                "assert 'numpy' not in sys.modules; "
                "assert 'sentinel_pulse.features' not in sys.modules",
            ],
            check=False,
        )
        self.assertEqual(result.returncode, 0)



if __name__ == "__main__":
    unittest.main()
