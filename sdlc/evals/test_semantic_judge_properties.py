"""
Property tests pinning what judge_engine.v1.semantic_judge actually does.

These are NOT aspirational. Every assertion below was verified against the
current source. They are written to PASS on today's code, so that the day
someone makes the judge actually semantic, this file goes red and tells them
which property they changed.

Two of them (the last two) are marked xfail: they assert what a judge SHOULD
do, and they fail today. That is the point. `pytest -rx` lists them.

Run:  python -m pytest sdlc/evals/test_semantic_judge_properties.py -q -rx
"""

import pytest

from judge_engine.v1 import semantic_judge


def score(artifact):
    return semantic_judge.evaluate(artifact, {})["semantic_score"]


# --- what it does today ----------------------------------------------------

def test_empty_artifact_scores_070():
    """An empty string scores 0.70. MEASUREDSTATE records 0.70 as an exact PASS,
    so submitting nothing at all clears the gate."""
    assert score("") == 0.7


def test_score_is_blind_to_correctness():
    """The single most important property. A correct implementation and a wrong
    one containing the same keywords are indistinguishable to the judge."""
    correct = "def add(a, b): return a + b"
    wrong = "def add(a, b): return a - b"
    assert score(correct) == score(wrong) == 0.74


def test_keyword_soup_outscores_working_code():
    """Four keywords and no program beats a correct one-liner that happens not
    to use them. The judge rewards token presence, not behaviour."""
    soup = "def  class  return  import "
    real = "x = sum(v for v in data if v > 0)"
    assert score(soup) == 0.78
    assert score(real) == 0.7
    assert score(soup) > score(real)


def test_output_space_is_25_values():
    """The reachable range is 0.50 to 0.78 in 25 discrete steps: 0.70 plus
    0.02 per positive token minus 0.05 per negative token. Any threshold placed
    inside that band separates keyword counts, not quality."""
    pos = ["def ", "class ", "return ", "import "]
    neg = ["TODO", "FIXME", "HACK", "XXX"]
    seen = {score("".join(pos[:k]) + "".join(neg[:m])) for k in range(5) for m in range(5)}
    assert len(seen) == 25
    assert min(seen) == 0.5 and max(seen) == 0.78


def test_bare_except_returns_a_silent_default():
    """evaluate() wraps _score in `except Exception` and returns 0.5. A None
    artifact raises TypeError inside _score and the caller receives a score,
    not an error. sdlc-v2 phase 6 gates on `grep for bare except = 0`; this is
    that grep hit, and it is in the judge itself."""
    assert score(None) == 0.5


def test_violations_are_hardcoded_empty():
    """hard_violations and process_violations are literal []. The judge cannot
    report a violation of any kind, for any artifact, ever."""
    hostile = "rm -rf / ; eval(input()); os.system(cmd)"
    out = semantic_judge.evaluate(hostile, {})
    assert out["hard_violations"] == []
    assert out["process_violations"] == []


def test_scope_is_ignored():
    """The scope argument is accepted and never read."""
    assert score("def f(): pass") == semantic_judge.evaluate(
        "def f(): pass", {"anything": "at all", "tenant": 42}
    )["semantic_score"]


# --- what a judge should do, and does not ----------------------------------

@pytest.mark.xfail(reason="judge is a substring counter; it cannot detect a wrong answer",
                   strict=True)
def test_wrong_implementation_should_score_lower():
    assert score("def add(a, b): return a + b") > score("def add(a, b): return a - b")


@pytest.mark.xfail(reason="hard_violations is hardcoded []", strict=True)
def test_obvious_hard_violation_should_be_reported():
    out = semantic_judge.evaluate("eval(input())  # arbitrary code execution", {})
    assert out["hard_violations"] != []
