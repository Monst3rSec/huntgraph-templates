"""Emerging threat intel: aggregate the feeds, score each item, write one CSV per run.

Self-contained on purpose. Nothing here imports `huntintel`, needs a model, or reads the
templates submodule, so the scheduled job installs three packages and runs.
"""
