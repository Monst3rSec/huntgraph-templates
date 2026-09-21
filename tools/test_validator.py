#!/usr/bin/env python3
"""Mutation test for tools/validate.py.

A validator that never fails is indistinguishable from no validator. This takes
a known-good detection file, injects one defect at a time, and asserts the
expected layer catches it. Run it whenever the schema or the validator changes.

    python3 tools/test_validator.py
"""

from __future__ import annotations

import copy
import json
import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import validate as V  # noqa: E402

GOOD = os.path.join(
    V.ROOT, "hunt", "endpoint", "T1218-system-binary-proxy-execution",
    "T1218.011-rundll32", "rundll32-user-writable-dll.yaml",
)


def m_unknown_key(d):
    d["hunt"] = {"window": "7d"}


def m_missing_version(d):
    del d["version"]


def m_bad_id_format(d):
    d["id"] = "rundll32_hunt"


def m_wrong_tactic(d):
    d["mitre"]["tactics"] = ["TA0006"]


def m_nonexistent_technique(d):
    d["mitre"]["techniques"] = ["T9999"]
    d["mitre"]["sub_techniques"] = []


def m_orphan_subtechnique(d):
    d["mitre"]["sub_techniques"] = ["T1055.012"]


def m_parent_level_hypothesis(d):
    # T1218 decomposes into sub-techniques, so a hypothesis declaring only the
    # parent is pitched too broadly to yield an explainable verdict
    d["mitre"]["sub_techniques"] = []


def m_wrong_detection_strategy(d):
    d["mitre"]["detection_strategies"] = ["DET0001"]


def m_analytic_not_in_strategy(d):
    d["mitre"]["analytics"] = ["AN0110"]


def m_platform_not_on_technique(d):
    d["mitre"]["platforms"] = ["Linux"]


def m_missing_technique_reference(d):
    d["info"]["references"] = ["https://example.org/blog"]


def m_duplicate_evidence_id(d):
    d["evidence"]["supporting"][1]["id"] = d["evidence"]["supporting"][0]["id"]


def m_verdict_unknown_id(d):
    d["evidence"]["verdict"]["high_risk_when"].append("no_such_evidence")


def m_risk_logic_required_mismatch(d):
    # non-empty (so L1 passes) but not the evidence.required set, which only
    # the semantic layer can notice
    d["evidence"]["risk_logic"]["required"] = ["suspicious_parent"]


def m_verdict_omits_required(d):
    d["evidence"]["verdict"]["suspicious_when"] = ["rare_dll_path"]


def m_contradicting_in_high_risk(d):
    d["evidence"]["verdict"]["high_risk_when"].append("vendor_install_path")


def m_undeclared_evidence_field(d):
    d["evidence"]["required"][0]["field"] = "MadeUpField"


def m_undeclared_evidence_source(d):
    d["evidence"]["required"][0]["source"] = "sysmon_magic"


def m_splunk_query(d):
    d["query"][0]["cases"][0]["query"] = (
        "index=edr sourcetype=ProcessRollup2 FileName=rundll32.exe\n| stats count by host"
    )


def m_kql_query(d):
    d["query"][0]["cases"][0]["query"] = (
        "ProcessRollup2\n| summarize count() by ComputerName\n| project ComputerName"
    )


def m_untagged_query(d):
    d["query"][0]["cases"][0]["query"] = (
        "FileName=/rundll32\\.exe/i\n| groupBy([ComputerName])\n| ProcessRollup2"
    )


def m_baseline_missing_window(d):
    d["query"][0]["cases"][0]["baseline"]["window"] = None


def m_baseline_missing_compare(d):
    d["query"][0]["cases"][0]["baseline"]["compare"] = []


def m_query_ignores_event_types(d):
    d["query"][0]["cases"][0]["query"] = (
        "#event_simpleName=SomeOtherEvent\n| FileName=/rundll32\\.exe/i\n| groupBy([ComputerName])"
    )


def m_foreign_platform(d):
    d["query"][0]["platform"] = "splunk"


def _cql_case(d, cid):
    return next(c for b in d["query"] if b["platform"] != "wazuh" for c in b["cases"]
                if c["id"] == cid)


def m_declared_field_never_returned(d):
    # the corpus's original failure: a field is declared, filtered on, and then
    # aggregated away, so the agent is asked to reason over telemetry the query
    # never hands back. Declared on the network source, which only an aggregating
    # case reads — a raw case would return the whole event and legitimately pass.
    d["requires"]["logs"][2]["fields"].append("SourceProcessId")


def m_field_collected_from_the_wrong_events(d):
    # naming a declared field in a collect() over events that never carry it
    # returns nothing; it must not count as returning the field
    d["requires"]["logs"][2]["fields"].append("SourceProcessId")
    c = _cql_case(d, "dll-write-then-rundll32-execute")
    c["query"] = c["query"].replace("collect([", "collect([SourceProcessId, ", 1)


CASES = [
    ("L1", "unknown top-level key rejected", m_unknown_key, None),
    ("L1", "missing required key rejected", m_missing_version, None),
    ("L1", "malformed id rejected", m_bad_id_format, None),
    ("L1", "non-crowdstrike platform rejected", m_foreign_platform, None),
    ("L2", "tactic not on the technique", m_wrong_tactic, None),
    ("L2", "technique that does not exist", m_nonexistent_technique, None),
    ("L2", "sub-technique without its parent", m_orphan_subtechnique, None),
    ("L2", "hypothesis pitched at a decomposing parent", m_parent_level_hypothesis, None),
    ("L2", "detection strategy not mapped to the technique", m_wrong_detection_strategy, None),
    ("L2", "analytic outside the declared strategy", m_analytic_not_in_strategy, None),
    ("L2", "platform not listed on the technique", m_platform_not_on_technique, None),
    ("L2", "technique URL missing from references", m_missing_technique_reference, None),
    ("L3", "duplicate evidence id", m_duplicate_evidence_id, None),
    ("L3", "verdict cites unknown evidence", m_verdict_unknown_id, None),
    ("L3", "risk_logic.required disagrees with evidence.required", m_risk_logic_required_mismatch, None),
    ("L3", "verdict tier omits required evidence", m_verdict_omits_required, None),
    ("L3", "contradicting evidence used to escalate", m_contradicting_in_high_risk, None),
    ("L3", "evidence field not declared in requires.logs", m_undeclared_evidence_field, None),
    ("L3", "evidence source not declared in requires.logs", m_undeclared_evidence_source, None),
    ("L4", "Splunk SPL in a CQL case", m_splunk_query, None),
    ("L4", "Microsoft KQL in a CQL case", m_kql_query, None),
    ("L4", "query with no event-stream tag", m_untagged_query, None),
    ("L4", "query ignoring every declared event type", m_query_ignores_event_types, None),
    ("L4", "baseline required without a window", m_baseline_missing_window, None),
    ("L4", "baseline required without comparators", m_baseline_missing_compare, None),
    ("L4", "declared field that no query returns", m_declared_field_never_returned, None),
    ("L4", "declared field only named in a collect() over the wrong events", m_field_collected_from_the_wrong_events, None),
]


def main() -> int:
    with open(V.SCHEMA_PATH) as fh:
        schema = json.load(fh)
    atk = V.Attack(V.load_bundle())

    with open(GOOD) as fh:
        base = yaml.safe_load(fh)

    # the control: the unmutated file must pass
    rep = V.Report(GOOD)
    if V.check_structure(base, schema, rep):
        V.check_mitre(base, atk, rep)
        V.check_evidence(base, rep)
        V.check_query(base, rep)
        V.check_query_emits_declared(base, rep)
        V.check_convention(base, GOOD, rep)
    failures = []
    if rep.errors:
        failures.append(("control", "unmutated fixture must validate clean", rep.errors))

    passed = 0
    for layer, label, mutate, _ in CASES:
        doc = copy.deepcopy(base)
        mutate(doc)
        r = V.Report(GOOD)
        if V.check_structure(doc, schema, r):
            V.check_mitre(doc, atk, r)
            V.check_evidence(doc, r)
            V.check_query(doc, r)
            V.check_query_emits_declared(doc, r)
            V.check_convention(doc, GOOD, r)
        caught = [e for e in r.errors if e.startswith("[%s]" % layer)]
        if caught:
            passed += 1
            print("  ok   %s  %s" % (layer, label))
        else:
            failures.append((layer, label, r.errors or ["<no errors at all>"]))
            print("  FAIL %s  %s" % (layer, label))

    print("\n%d/%d mutations caught" % (passed, len(CASES)))
    for layer, label, errs in failures:
        print("\nFAILED %s %s" % (layer, label))
        for e in errs:
            print("   %s" % e)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
