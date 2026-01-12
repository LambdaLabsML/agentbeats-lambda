# Badblueprint Submission Bundle

CI runs the vendored harness in `--serve-only` mode as an offline smoke test.
To run full scoring locally with your own API key:

```bash
python scripts/export_badblueprint_submission.py
python scripts/validate_submission_bundle.py submissions/purple_vanguard/badblueprint
pip install -e vendor/agentbeats-lambda
export OPENAI_API_KEY=...  # set locally
export OPENAI_BASE_URL=...  # optional, if using a compatible endpoint
agentbeats-run submissions/purple_vanguard/badblueprint/scenario_badblueprint.toml
```