# Open day demo runbook

Total demo time: about 7 minutes. Everything below runs on your laptop: WSL Ubuntu (server, dashboard, Ollama), and two VirtualBox VMs (the protected machine and the attacker).

## 0. One-time setup (do it at least two days before)

### A. Create the attacker VM
1. VirtualBox: right-click `shield-endpoint` > Clone. Name it `shield-attacker`. Choose **Full clone** and **Generate new MAC addresses for all network adapters**.
2. Start it, log in as `lab`, and give it its own identity (otherwise both VMs ask for the same IP address):
   ```bash
   sudo hostnamectl set-hostname shield-attacker
   sudo rm -f /etc/machine-id /var/lib/dbus/machine-id
   sudo systemd-machine-id-setup
   sudo reboot
   ```
3. After the reboot, run `ip -4 addr show enp0s8` and note the address. It must differ from `192.168.56.103`. This is your ATTACKER_IP.
4. Install the attack tools: `sudo apt-get install -y nmap hping3`
5. From WSL, copy the attack scripts: `scp demo/attack_scan.sh demo/attack_flood.sh lab@ATTACKER_IP:~/`
6. Check the two VMs can reach each other: `ping -c 2 192.168.56.103` from the attacker VM.

Why a second VM: the protected VM refuses to block your laptop (192.168.56.1), because that is also the Shield server. The attacker must have its own address so Block can really cut it off.

### B. Optional but recommended: train on real normal traffic
The model you have now learned "normal" from synthetic data. For a defensible evaluation, retrain it on traffic recorded from your own VM.
1. WSL: `bash demo/sync_agent_to_vm.sh` (updates the agent code in the VM).
2. VM terminal 1 (stop the running sensor first with Ctrl+C):
   ```bash
   sudo env PYTHONPATH=$HOME/shield/agent/src:$HOME/shield/shared/shield_common/src SHIELD_AGENT_CONFIG=$HOME/vm-config.json $HOME/venv/bin/python -m shield_agent record --interface all --seconds 600 --out $HOME/lab_benign.jsonl
   ```
3. VM terminal 2, at the same time: `bash normal_traffic.sh 60` (copy `demo/normal_traffic.sh` to the VM first).
4. WSL, after 10 minutes:
   ```bash
   scp lab@192.168.56.103:~/lab_benign.jsonl ml/data/
   python ml/scripts/train_model.py --input ml/data/lab_benign.jsonl
   docker compose -f deploy/docker-compose.yml restart backend-worker
   ```
5. Restart the sensor in the VM (command in section 1).
The detection percentages the script prints still use my synthetic attack shapes. Do not present them as results. Use the live demo and your own stopwatch measurements instead (see the presentation outline).

### C. Record a backup video
After one clean rehearsal, record the full run (Windows: Win+Alt+R). Keep two copies, one on the laptop and one on a USB stick.

## 1. Start order on the day (30 minutes before)
1. Plug in the laptop. Close everything you do not need (RAM is tight: close browser tabs).
2. VirtualBox: start `shield-endpoint` and `shield-attacker`.
3. WSL: make sure Ollama is running and has the model in memory:
   ```bash
   OLLAMA_HOST=0.0.0.0 ollama serve        # skip if it already runs as a service
   ollama run llama3.2:3b                   # say hi, wait for the answer, then type /bye
   ```
4. WSL: `docker compose -f deploy/docker-compose.yml up -d`
5. WSL, a second tab: `cd frontend && npm run dev`
6. VM `shield-endpoint`:
   ```bash
   sudo env PYTHONPATH=$HOME/shield/agent/src:$HOME/shield/shared/shield_common/src SHIELD_AGENT_CONFIG=$HOME/vm-config.json $HOME/venv/bin/python -m shield_agent run
   ```
7. WSL: `bash demo/preflight.sh`. Fix every FAIL it prints.
8. `bash demo/reset.sh` so you start with an empty dashboard.
9. Browser: open `http://localhost:5173` and sign in **right before you start**. The login lasts 15 minutes.
10. Put the attacker VM terminal next to the browser.

## 2. The demo (about 7 minutes)

| Step | You do | They see | You say |
|---|---|---|---|
| 1 | Show the empty dashboard | "0 open", `vm-sensor online` | "Laptop Shield watches the network traffic of a protected laptop. Right now it is quiet." |
| 2 | Attacker VM: `bash attack_scan.sh 192.168.56.103` | nmap scanning | "I am playing the attacker: a port scan, the first step of most attacks." While it runs, explain the pipeline in one sentence: sensor, flows, rules plus a learning model, explanation, your decision. |
| 3 | Wait about 15 to 25 seconds. A "new" alert appears; click it | Headline "… probed N ports", severity, gauge, rule matched | "Two detectors agree: a fixed rule and an unsupervised model that learned normal traffic." |
| 4 | Point at the assistant box | Plain-English explanation, "Suggests: Block" | "A small language model running locally explains it. It only advises; it never acts." |
| 5 | Click Block (15 minutes), click again to confirm | "What was done": waiting, then "Done on the machine" | "The server told the agent, and the agent added a firewall rule on the protected machine." |
| 6 | Attacker VM: run the scan again | nmap reports all ports filtered | "The attacker is now cut off." |
| 7 | Click Unblock now | Log shows the unblock | "Blocks are time-limited and reversible." |
| 8 | WSL: `bash demo/reset.sh`. Attacker VM: `bash attack_flood.sh 192.168.56.103` | Second alert, "SYN flood" (allow about 25 s) | "A different attack, detected by rate instead of by ports." Show Allow vs Dismiss vs Block, then explain why a human decides. |
| 9 | Close | | "Detection is automatic, the decision stays with the person, and the language model never sees raw network data." |

Why step 8 needs the reset: the system raises one alert per attacker address per 5 minutes on purpose, so a repeated attack from the same address does not flood the screen.

### Attack menu (what each script shows)

| Script (run on the attacker VM) | What it simulates | Alert label | Time to alert |
|---|---|---|---|
| `bash attack_scan.sh 192.168.56.103` | Port scan of ports 1 to 1000 | Port scan | about 15 to 25 s |
| `bash attack_flood.sh 192.168.56.103` | SYN flood: 3000 unfinished connections | SYN flood | about 20 to 30 s |
| `bash attack_bruteforce.sh 192.168.56.103` | Password guessing against SSH (40 failed logins) | Password guessing | about 15 to 25 s |
| `bash simulate_beacon.sh ATTACKER_IP` (run **inside the protected VM**; start `bash beacon_listener.sh` on the attacker VM first) | Malware phoning home every 10 s | Regular check-ins | about 90 s |

Copy each script with `scp demo/attack_*.sh lab@ATTACKER_IP:~/`. Always run `bash demo/reset.sh` between two attacks (one alert per attacker address per 5 minutes is deliberate).

Beaconing is the one scene where the protected VM is the source. Block therefore cuts off the *remote* address (the attacker VM) in both directions, and the check-ins stop. Use it as an optional extra scene: it needs 90 seconds of narration (explain the timing analysis while you wait).

What the system does not detect: attacks hidden inside encrypted traffic (web exploits, malware downloads), anything that happens only inside the machine (a malicious program running), attacks on other computers, and very slow scans. Say this in the presentation before an examiner asks.

## 3. If something goes wrong

| Symptom | Likely cause | Fix |
|---|---|---|
| No alert after 40 s | Sensor stopped, wrong target IP, or the 5-minute dedupe | Check the sensor window is still running, run `bash demo/preflight.sh`, run `bash demo/reset.sh`, re-run the attack |
| Assistant says "Writing an explanation…" for a long time | Model not loaded in Ollama | Keep talking: a standard-wording explanation appears within about 90 s. Next time warm the model (section 1, step 3) |
| Block stays on "Waiting for the agent" | Sensor stopped or cannot reach the server | Restart the sensor in the VM |
| Log says "refused: this machine or the Shield server" | The attack came from the laptop's own address | Run the attack from the attacker VM |
| nmap shows the host as down before you blocked | An old block is still active | Click Unblock now, or see `demo/reset.sh` |
| "Your session expired" | 15-minute login ended | Sign in again |
| Everything is slow | Out of memory | Close other programs, check `docker stats` |

## 4. Backup plan
If the live demo fails and a quick fix does not work within a minute, say so calmly and play the recorded video. Examiners value a working system that you can explain over a flawless live run.

## 5. Suggested schedule for the last days
- Day 5: attacker VM, one full run, preflight script.
- Day 6: two rehearsals with a stopwatch, record the backup video, write down the time from scan to alert (3 runs).
- Day 7: one short rehearsal, prepare the slides, close everything and sleep.
