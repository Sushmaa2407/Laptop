BATCH 3 - LLM explainer
1. Unzip at the repo root.
2. deploy/docker-compose.yml: paste deploy/docker-compose.explainer.snippet.yml under "services:".
3. Make Ollama listen to Docker (see chat), pull the model: ollama pull llama3.2:3b
4. docker compose -f deploy/docker-compose.yml up -d --build
5. docker compose -f deploy/docker-compose.yml logs backend-explainer --tail 20
