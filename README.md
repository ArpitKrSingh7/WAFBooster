# WAFBooster source code

WAFBooster is a research prototype that learns additional ModSecurity rules from payloads that pass a local Web Application Firewall (WAF). The project combines a Dockerized ModSecurity CRS testbed, a labeled payload dataset, neural models for payload learning and generation, a correction stage, and an automatically generated rule set.

All traffic in the reproduction workflow is sent to the local WAF at `http://localhost:8080`. The companion Flask application is a minimal backend used by the Docker testbed.

## Pipeline overview

1. **Start the testbed.** `docker-compose.yml` runs an OWASP ModSecurity CRS Nginx service published on host port 8080 and the Flask backend on container port 5000 (available to the WAF service on the Compose network).
2. **Build a labeled dataset.** `src/dataset.py` extracts benign query values from the CSIC 2010 input, creates SQL injection variants, asks the live WAF to label them, and writes stratified train, validation, and test splits.
3. **Train the shadow classifier.** `src/shadow_model.py` trains 128-dimensional Word2Vec embeddings and a ShadowCNN classifier using the training split.
4. **Generate candidate payloads.** `src/payload_generator.py` trains a GRU on malicious training payloads and samples candidate payloads.
5. **Correct candidates.** `src/payload_corrector.py` applies the project's token-distance correction rules and filters candidates.
6. **Produce and deploy signatures.** `src/signature_producer.py` finds candidates that bypass the baseline WAF, derives signatures, checks benign samples, writes ModSecurity rules, and attempts to deploy them to the running WAF container.
7. **Evaluate generalization.** `src/evaluate_held_out.py` compares baseline and boosted WAF behavior on held-out samples and newly generated candidates, then saves a results table.

## Repository contents

```text
.
├── app.py                              # Flask echo/search backend used by the testbed
├── test_waf.py                         # Prints responses for one benign and one SQL injection request
├── Dockerfile                          # Builds the Flask backend image
├── docker-compose.yml                  # Backend and ModSecurity CRS services
├── archive/
│   └── csic_database.csv               # CSIC 2010 input dataset used for benign examples
├── src/
│   ├── waf_client.py                   # HTTP client for the local WAF; 403 -> blocked (1)
│   ├── dataset.py                      # Payload mutation, WAF labeling, and data splitting
│   ├── shadow_model.py                 # SQL-aware tokenizer, Word2Vec, and ShadowCNN
│   ├── payload_generator.py            # GRU training and synthetic candidate generation
│   ├── payload_corrector.py             # Candidate correction and filtering
│   ├── signature_producer.py            # Signature learning, rule creation, and deployment
│   └── evaluate_held_out.py             # Baseline-versus-boosted held-out evaluation
├── data/processed/                      # Dataset splits and generated pipeline CSVs
├── models/                              # Saved Word2Vec, CNN, GRU, and vocabulary artifacts
├── rules/wafbooster_rules.conf          # ModSecurity rule configuration
└── results/held_out_evaluation.csv      # Saved evaluation table
```

The files in `models/` are `word2vec.model` (token embeddings), `shadow_cnn.pt` (classifier weights), `payload_gru.pt` (generator weights), and `vocab.pkl` (token-to-ID and ID-to-token mappings).

### Generated CSVs

- `train.csv`, `val.csv`, `test.csv`: labeled splits with `payload`, `source`, and `waf_label` columns. `source` identifies benign or malicious examples; `waf_label` is `0` for allowed and `1` for blocked.
- `generated_candidates.csv`: raw payload candidates sampled by the GRU.
- `corrected_candidates.csv`: generated candidates retained by the correction stage, with original and corrected payloads and a status.
- `bypassing_payloads.csv`: candidates allowed by the baseline WAF when signatures are produced.
- `signatures.csv`, `signatures_learned_only.csv`, `signatures_full.csv`: learned signature output and the learned-only/full sets used for the ablation comparison.
- `novel_generated.csv`: fresh GRU samples used by the held-out evaluation.

The checked-in processed CSVs, model files, rules, and result table are useful as reference artifacts. The commands below regenerate the pipeline outputs from the included CSIC input and the local WAF.

## Requirements

- Python 3 with `pip`
- Docker Engine and the Docker Compose plugin
- Enough memory and disk space for PyTorch and model training; a CUDA GPU is optional

From the repository root, install the Python packages used by the scripts:

```bash
python3 -m pip install pandas numpy gensim torch rapidfuzz requests scikit-learn
```

Flask is installed in the backend image by the `Dockerfile`. The container image for ModSecurity CRS is pulled by Docker Compose.

## Run the end-to-end pipeline

Run commands from the repository root because scripts use paths relative to it. The `-p is` project name gives the WAF container the `is-waf-1` name expected by the rule deployment and evaluation scripts. If running from the original checkout directory named `is`, the report's `docker compose up --build -d` command also yields that name.

```bash
# Start the local Flask backend and ModSecurity CRS WAF.
docker compose -p is up --build -d

# Optional manual check: print responses to a benign request and a SQL injection request.
python3 test_waf.py

# Reproduce the data, learning, rule-generation, and evaluation stages in order.
python3 src/dataset.py
python3 src/shadow_model.py
python3 src/payload_generator.py
python3 src/payload_corrector.py
python3 src/signature_producer.py
python3 src/evaluate_held_out.py
```

Wait for the WAF service to finish starting before sending requests. Expected artifacts are written under `data/processed/`, `models/`, `rules/`, and `results/`. `signature_producer.py` and `evaluate_held_out.py` need Docker access to update and reload the running WAF container. The evaluation stage switches the WAF between baseline and boosted rules while it measures results.

Stop the local services when finished:

```bash
docker compose -p is down
```

## Individual modules

`src/waf_client.py` sends a payload as the `q` parameter to `/search` and returns `1` for HTTP 403, `0` for other HTTP responses, or `None` after connection failures. `test_waf.py` provides a minimal manual check of this behavior against the running service.

The full pipeline is designed to run in the order shown above. In particular, the model training and candidate stages consume CSVs produced by earlier stages, and final evaluation needs the generated models, `rules/wafbooster_rules.conf`, the held-out split, and a running Docker testbed.
