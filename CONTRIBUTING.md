# Contributing

Open an issue describing the problem, expected behavior, and a minimal synthetic example. For a code change, keep dependencies in the standard library unless there is a documented need, preserve offline operation, and include meaningful regression coverage for changed detection behavior.

Run `python -m unittest discover -s tests -v` and `python -m compileall -q traceguard.py tests` before submitting a pull request. Explain threshold or grouping changes, migration effects on case IDs, and false-positive tradeoffs. Use documentation IP ranges and invented accounts in examples. Do not commit databases, generated reports, credentials, or real investigation evidence.
