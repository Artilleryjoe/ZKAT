.PHONY: demo test

demo:
	python -m zkat.agent.zkat_agent --nmap-xml tests/data/sample_nmap.xml --output-dir ./out --state-dir ./state --private-key ./state/agent.key --skip-git
	@RUN_DIR=$$(find ./out -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1); \
	python -m zkat.verifier.zkat_verify --attestation $$RUN_DIR/attestation.json --signature $$RUN_DIR/signature.json --canonical $$RUN_DIR/canonical.json --email $$RUN_DIR/email/$$(basename $$RUN_DIR).eml --require-zk

test:
	pytest
