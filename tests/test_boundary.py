from judge_engine.v1.engine import classify
from judge_engine.v1.engine import VERDICT_PASS, VERDICT_WARN
from api.constants import SCORE_PASS, SCORE_WARN

def test_pass_boundary_exact():
    assert classify(SCORE_PASS, []) == VERDICT_PASS

def test_warn_boundary_exact():
    assert classify(SCORE_WARN, []) == VERDICT_WARN
