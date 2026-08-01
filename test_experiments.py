import unittest

from intersection_analysis import run_intersection
from saliency_analysis import run_saliency, wilson_interval


class ExperimentTests(unittest.TestCase):
    def test_wilson_interval_contains_observed_rate(self):
        low, high = wilson_interval(10, 100)
        self.assertLess(low, 0.1)
        self.assertGreater(high, 0.1)

    def test_saliency_collects_both_sources(self):
        result = run_saliency(
            [2], train_lists=8, test_lists=12, field_count=2,
            domain_size=2, seed=1,
        )
        self.assertEqual(
            {row["decoy_source"] for row in result["summary"]},
            {"uniform", "matched"},
        )
        self.assertTrue(all(row["test_lists"] == 12 for row in result["summary"]))

    def test_intersection_collects_both_strategies_and_raw_trials(self):
        result = run_intersection(
            universe_size=20, candidate_size=4, sessions=3,
            trials=10, seed=1,
        )
        self.assertEqual(len(result["summary"]), 6)
        self.assertEqual(len(result["raw_intersection_sizes"]), 10)
        self.assertTrue(
            all(len(sample) == 3 for sample in result["raw_intersection_sizes"])
        )


if __name__ == "__main__":
    unittest.main()
