"""
Baseline defender security gateway package for the Security Arena.

This package implements a simple, rule-based security pipeline in front
of the underlying LLM. The design is intentionally minimal and
competition-compliant:

- All attack detection is rule-based (no LLM calls).
- At most a single LLM call is made per request.
- Robust error handling ensures the defender never crashes.

"""

