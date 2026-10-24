# Usage report

The final full-dataset run is local and deterministic:

```text
python code/main.py --requests dataset/deletion_requests.csv --output output.csv
```

- Model provider: none
- Model name: none
- Model calls: 0
- Input tokens: 0
- Output tokens: 0
- Total tokens: 0
- Average tokens per request: 0
- Estimated total cost: $0
- Estimated cost per request: $0

The agent intentionally does not require credentials or send evidence to an
external service. An LLM or vision adapter can be added behind the evidence
extraction boundary later, but policy enforcement, temporal filtering, status
decisions, output validation, and serialization remain deterministic.
