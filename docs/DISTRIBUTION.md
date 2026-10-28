# Distributing the sensor to other users

The idea: a user signs up, opens the **Devices** page, creates an install command and runs it on their laptop. Only the small sensor is installed there. Detection, explanations and the dashboard stay on your server.

## What the user does
1. Sign in to the dashboard and open **Devices**.
2. Type a name for the laptop, check the server address, click **Create install command**.
3. Run the command on the laptop (Linux, Python 3.11 or newer, as root through `sudo`). The sensor is downloaded, its checksum is verified, the laptop is enrolled, and a background service starts. The laptop shows up under **Your devices** within about 30 seconds.

To remove it: `curl -fsSL SERVER/api/v1/downloads/uninstall.sh | sudo bash`, then delete nothing else; the sensor lifts its own firewall blocks.

## What you (the operator) do once
1. Build the downloadable files (in WSL, from the repo root):
   `bash scripts/build_agent_bundle.sh ./caddy-root.crt`
   The certificate argument is only for lab setups where the server uses its own certificate authority. Leave it out when the server has a normal public certificate. Re-run this command whenever the sensor code changes.
2. Add the line from `deploy/docker-compose.downloads.snippet.yml` to the `backend-api` service, add `dist/` to `.gitignore`, and restart: `docker compose -f deploy/docker-compose.yml up -d --build`
3. Check it: `curl -s --cacert ./caddy-root.crt https://localhost/api/v1/downloads/agent-linux.tgz.sha256`
4. Run the tests: `cd backend && pytest`. The download routes are public on purpose. If your route-security test lists the public routes, add `/api/v1/downloads/...` to that list.

## Testing it with a second user in the lab
1. Register a second account (the Swagger page at `/docs`, as before). Sign in with it in a private browser window. It gets its own empty workspace.
2. In that window: Devices > Create install command. Leave "own certificate authority" ticked and the address as `https://shield.lab`.
3. On the attacker VM (Ubuntu 24.04 has the right Python), make sure `shield.lab` resolves: `echo "192.168.56.1 shield.lab" | sudo tee -a /etc/hosts`, then run the command.
4. The attacker VM appears under the second user's devices, and **not** under your first account. That is the tenant separation working.
5. The sensor now runs on the attacker VM too, so stop it before running attacks from there: `sudo systemctl stop shield-agent` (start it again with `start`). Otherwise the second user sees the attacks as alerts, which is also a fine demo.

## Making it reachable from other networks (not done, not tested)
- Rent a small cloud machine, point a domain name at it, and put the Docker stack on it. Caddy can obtain a normal public certificate by itself, and then users do not need the certificate option at all.
- Set `SHIELD_PUBLIC_URL=https://your.domain` for the backend so the install script always carries the right address, and `COOKIE_SECURE=true`.
- Open only ports 80 and 443 to the internet. Keep the database and Redis private. Back up the database.
- The explanation service needs a model server. On a small cloud machine without a graphics card the 3-billion-parameter model is slow; the standard-wording fallback then does the job.

## Security notes
- The install command pipes a script into a shell. That is normal for installers but means users must trust your server. The checksum protects against a damaged or swapped download file, not against a malicious server.
- The enrollment code is the secret. It works once and expires in a few minutes.
- "Own certificate authority" mode trusts the server's certificate on first use and prints its fingerprint. Use a public certificate for real users.

## Limits
- The sensor runs on Linux only. A Windows sensor needs a different packet capture method and the Windows Firewall; it is future work.
- Blocks use `iptables`; a laptop without it still gets alerts but cannot block.
