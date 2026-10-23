#!/bin/sh

. nvram_ops

# --- Configuration ---
tinc_port=655
tinc_ddos_log=1
tinc_ban_seconds=604800      # 1 week in seconds
tinc_detect_seconds=86400    # 1 day in seconds
tinc_detect_hitcount=2

chain_name="TINC_PROTECT"
recent_list="tinc_blocked"

do_stop() {
  while true; do
    line=$(iptables -L INPUT -n --line-numbers 2>/dev/null | grep -E "$chain_name|dpt:$tinc_port" | tail -n 1 | awk '{print $1}')
    [ -n "$line" ] && iptables -D INPUT "$line" 2>/dev/null || break
  done
  iptables -F "$chain_name" 2>/dev/null
  iptables -X "$chain_name" 2>/dev/null
  for p in /proc/net/xt_recent /proc/net/ipt_recent; do
    [ -e "$p/$recent_list" ] && echo 0 > "$p/$recent_list" 2>/dev/null
  done
}

do_start() {
  do_stop >/dev/null 2>&1
  iptables -N "$chain_name"
  [ "$tinc_ddos_log" -eq 1 ] && iptables -A "$chain_name" -m limit --limit 3/m -j LOG --log-prefix "TINC_DDOS_DROP: " --log-level 4
  iptables -A "$chain_name" -j DROP

  # Whitelist FQDNs fetched via NG (nvram get)
  for host in $(NG tinc_hosts | sed 's/[#!].*//' | grep -Eo '((([a-zA-Z]{1,2})|([0-9]{1,2})|([a-zA-Z0-9]{1,2})|([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]))\.)+[a-zA-Z]{2,6}' | sort -u); do
    iptables -A INPUT -p udp --dport "$tinc_port" -s "$host" -j ACCEPT
  done

  iptables -A INPUT -p udp --dport "$tinc_port" -m recent --name "$recent_list" --rcheck --seconds "$tinc_ban_seconds" --hitcount "$tinc_detect_hitcount" -j "$chain_name"
  iptables -A INPUT -p udp --dport "$tinc_port" -m recent --name "$recent_list" --set -m limit --limit 3/sec --limit-burst 5 -j ACCEPT
  iptables -A INPUT -p udp --dport "$tinc_port" -j "$chain_name"
  echo "[+] Tinc DDoS protection active."
}

do_status() {
  echo "=== [ Service Status ] ==="
  iptables -L "$chain_name" >/dev/null 2>&1 && echo -e "Status: ${f_green}RUNNING${reset}" || echo -e "Status: ${f_red}STOPPED${reset}"
  echo ""
  echo "=== [ Configuration ] ==="
  echo "Detection Window : $tinc_detect_seconds sec ($((tinc_detect_seconds / 86400)) day/s)"
  echo "Detection Trigger: $tinc_detect_hitcount hit(s)"
  echo "Ban Window       : $tinc_ban_seconds sec ($((tinc_ban_seconds / 86400)) day/s)"
  echo "Logging Enabled  : $tinc_ddos_log"
  echo ""
  echo "=== [ Rules & Packet Counts ] ==="
  iptables -L "$chain_name" -v -n 2>/dev/null || echo "Chain does not exist."
  echo ""
  echo "=== [ Currently Blocked IPs ] ==="
  for p in /proc/net/xt_recent /proc/net/ipt_recent; do
    [ -e "$p/$recent_list" ] && cat "$p/$recent_list" && break
  done
}

case "${1:-start}" in
  start) do_start ;;
  stop) do_stop; echo -e "[-] Tinc DDoS protection ${f_red}stopped${reset}." ;;
  status) do_status ;;
  *) echo "Usage: $0 {start|stop|status}"; exit 1 ;;
esac
