.PHONY: install run test lint clean caps demo

install:
	./scripts/install.sh

run:
	./scripts/run.sh

test:
	./scripts/test.sh

caps:
	python3 -c "from backend import capabilities; import json; print(json.dumps(capabilities.report(), indent=2, default=str))"

demo:
	./scripts/demo.sh

clean:
	rm -rf .pytest_cache **/__pycache__ 2>/dev/null || true
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true

echo "targets: install run test caps demo clean"
