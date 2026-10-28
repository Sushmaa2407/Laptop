#!/usr/bin/env bash
# Run on the ATTACKER VM:   bash attack_bruteforce.sh 192.168.56.103 [COUNT]
# Password guessing against SSH: many quick login attempts with made-up user names. Every attempt is a new
# connection to port 22, which is what the "password guessing" rule counts (10 or more within a minute).
# No extra tools needed. (With hydra installed you can use:  hydra -l lab -P words.txt -t 4 ssh://TARGET )
TARGET="${1:?usage: bash attack_bruteforce.sh TARGET_IP [COUNT]}"
COUNT="${2:-40}"
echo "Making $COUNT failed SSH logins against $TARGET ..."
for i in $(seq 1 "$COUNT"); do
  ssh -o BatchMode=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 \
      "guest$i@$TARGET" true >/dev/null 2>&1
  printf '.'
done
echo
echo "Done. Watch the dashboard (allow about 20 seconds)."
