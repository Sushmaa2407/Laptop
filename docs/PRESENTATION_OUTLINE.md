# Presentation outline (12 slides, about 12 minutes including the demo)

1. **Title and problem.** Laptops on shared networks get scanned and attacked, small teams have no security operations centre, and traditional antivirus mostly looks for known signatures.
2. **The idea in one sentence.** A small agent watches a laptop's network traffic, a server spots attacks and explains them in plain English, and a person decides what to block.
3. **Architecture.** Draw: agent (Linux) > HTTPS > FastAPI > Redis queue > detection worker (rules + ONNX model) > PostgreSQL > explainer (local Ollama) > React dashboard > command back to the agent > firewall rule. Mention Docker Compose and the Caddy HTTPS front door.
4. **The sensor.** Raw packets are parsed defensively, grouped into flows, and turned into 13 numeric features. The same feature code is used for training and live detection, so the model sees numbers computed the same way in both places.
5. **Detection.** Two detectors: fixed rules (port scan, host sweep, SYN flood, password guessing) and an Isolation Forest trained only on normal traffic. A temporal layer looks for machines that contact the same address at a regular rhythm (autocorrelation computed with the FFT), which is typical of malware beaconing. A severity policy combines everything. When detectors disagree the dashboard says so instead of hiding it.
6. **Human in the loop and safety.** The language model only explains and advises. Its answer must be valid JSON, may only mention numbers and addresses from the evidence, and falls back to a fixed template otherwise. The agent refuses to block itself or the server, blocks expire, and every action is audited.
7. **Securing the platform itself.** Tenant isolation tests, hashed API keys, rate limiting, HTTPS, and a CI pipeline with lint, tests, dependency audit and secret scanning.
8. **Live demo.** Follow `docs/DEMO_RUNBOOK.md`.
9. **Results (be honest).** Show: time from attack start to alert (your stopwatch, 3 runs), which attacks were detected (port scan, SYN flood), false alerts on recorded normal traffic, and the test count. State clearly that the baseline was trained on traffic from your own lab.
10. **Limitations.** Features come from single flows, the lab is small, encrypted payloads are not inspected, only a Linux agent exists, the 3-billion-parameter model can still word things badly (hence the guardrails), and slow "low and slow" scans can evade the rate rules, and legitimate software that checks in regularly (update checkers, monitoring) looks like beaconing, so a person must decide.
11. **Future work.** Windows agent, baseline-drift analysis, evaluation on the public CICIDS2017 dataset, a user study of the explanations, notifications by email or chat.
12. **Conclusion and questions.**

## Things from the original plan that are not built
The original plan also mentioned an A/B evaluation on CICIDS2017, a Windows agent, and a baseline-drift measure inside the temporal layer. They are not implemented. Do not claim them in the report or slides. Put them under future work. The temporal layer that exists measures regular timing (periodicity) only.

## Questions to prepare for
- **Why Isolation Forest?** It needs only normal traffic to train, runs in microseconds through ONNX, and does not need labelled attacks.
- **Why both rules and a model?** Rules are precise for known patterns, the model can flag the unfamiliar. Showing both, and where they disagree, is more honest than one score.
- **What if the language model is wrong?** It cannot act. Its text is checked against the evidence, and a fixed template replaces it when the check fails. A person always decides.
- **How do you avoid blocking innocent addresses?** Humans approve, blocks expire, an allowlist exists, and the agent never blocks itself or the server.
- **How is this different from Snort or Suricata?** Those match signatures. This learns a baseline, explains alerts in plain language, and closes the loop to the firewall with an approval step.
- **What about evasion?** Slow scans can stay below the rate thresholds. That is a known limit and the temporal layer in future work targets it.
- **Does it scale?** Ingestion is queued in Redis and workers can be added. It was tested at lab scale only.
- **Privacy?** The language model runs on the same laptop and sees only numbers and addresses from alerts, never packet contents.
