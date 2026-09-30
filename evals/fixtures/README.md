# BLOCK fixtures — prove every hard gate can fire

A gate that has never been seen to BLOCK is decoration, not protection.
For EVERY `blocking: hard` row in `../registry.yaml`, keep one candidate
fixture here that breaches ONLY that metric (all other metrics healthy),
plus one `healthy.json` that PROMOTEs clean. Then assert both in a test:

    python evals/tools/promote.py --candidate evals/fixtures/block_<metric>.json
    # must exit 1, blocking exactly <metric>

    python evals/tools/promote.py --candidate evals/fixtures/healthy.json
    # must exit 0

For `lower_better` metrics (latency, cost) the breach value is ABOVE the
threshold — the most common fixture mistake.

Add a coverage check so a new hard row forces a new fixture: list the hard
rows from the registry, list the block_*.json files, assert the sets match.
