"""Application services: orchestration, querying, scoring and storage.

Security-sensitive logic (quarantine handling, scoring weights) lives here and
in `analyzers/`, never in the API layer. Routes validate and delegate.
"""
