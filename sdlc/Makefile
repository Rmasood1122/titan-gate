# titan-gate -- the Makefile IS the documentation. Every target is a gate.
.PHONY: status predict label seal gate validate

status:            ## where the scoreboard actually stands
	@echo "== prediction log =="; python3 evals/predict.py status || true
	@echo; echo "== golden set =="; python3 evals/label.py --status || true

predict:           ## make predict Q="how many X?"
	@python3 evals/predict.py ask "$(Q)"

label:             ## label cases into the golden set (resumable)
	@python3 evals/label.py --limit $(or $(N),25)

seal:              ## freeze a 20% holdout once the floor is reached
	@python3 evals/label.py --seal

validate:          ## make validate F=response_001.json
	@python3 evals/validate_response.py $(F)

gate:              ## the only definition of done
	@python3 evals/validate_response.py --selftest >/dev/null && echo "validator      : live" || echo "validator      : DEAD"
	@python3 evals/label.py --status | tail -1
	@python3 evals/predict.py status | tail -1
	@python3 evals/label.py --verify-seal 2>/dev/null || echo "holdout        : not sealed yet"
