from scapy.all import sniff, TCP, IP
from datetime import datetime
from collections import deque, Counter
import requests
import os
import json
import sys

guard_port = 8443
guard_ip = "" # IP PUBLICO DO PROPIO NODO
relay_list_file = "tor_relays.txt"

tor_relays = set()
client_buffers = {}
used = set()
pair_counts = Counter()  # (client_ip, middle_ip) → contagem
matches = 0


def save(matches, client_ip, middle_node):
    with open("found.log", 'a') as f:
        f.write(json.dumps({"id": matches, "client":client_ip, "middle": middle_node, "data": str(datetime.now())}) + "\n")


def download_tor_relays():
    print("Baixando lista de relays...", flush=True)
    try:
        resp = requests.get("https://onionoo.torproject.org/summary", timeout=30)
        data = resp.json()
        relays = set()
        for relay in data.get('relays', []):
            for addr in relay.get('a', []):
                ip = addr.split(':')[0]
                relays.add(ip)
        with open(relay_list_file, 'w') as f:
            f.write(f"# {len(relays)} relays - {datetime.now()}\n")
            for ip in sorted(relays):
                f.write(f"{ip}\n")
        print(f"✓ {len(relays)} relays salvos")
        return relays
    except Exception as e:
        print(f"✗ Erro: {e}")
        return set()

def load_tor_relays():
    global tor_relays
    if os.path.exists(relay_list_file):
        print("Carregando cache...")
        with open(relay_list_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    tor_relays.add(line)
        print(f"✓ {len(tor_relays)} relays carregados")
    else:
        tor_relays = download_tor_relays()
    tor_relays.discard(guard_ip)

def process_packet(pkt):
    global matches

    if IP not in pkt or TCP not in pkt:
        return

    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]
    ts = float(pkt.time)
    pkt_len = len(pkt)

    if pkt_len < 100:
        return

    # ENTRADA: cliente → guard:8443
    if ip_layer.dst == guard_ip and tcp_layer.dport == guard_port:
        client_ip = ip_layer.src
        if client_ip not in client_buffers:
            client_buffers[client_ip] = deque(maxlen=200)
        client_buffers[client_ip].append({"ts": ts, "len": pkt_len})

    # SAÍDA: guard → middle
    elif ip_layer.src == guard_ip and ip_layer.dst in tor_relays:
        middle_ip = ip_layer.dst
        middle_port = tcp_layer.dport

        best_client = None
        min_diff = float('inf')

        for client_ip, buf in client_buffers.items():
            for pkt_in in list(buf):
                pkt_id = (pkt_in["ts"], client_ip)
                if pkt_id in used:
                    continue

                time_diff = ts - pkt_in["ts"]
                if 0 < time_diff <= 0.02:  # janela 20ms
                    size_ratio = pkt_in["len"] / pkt_len
                    if 0.8 <= size_ratio <= 1.2:
                        if time_diff < min_diff:
                            min_diff = time_diff
                            best_client = (client_ip, pkt_in)

        if best_client:
            client_ip, pkt_in = best_client
            pkt_id = (pkt_in["ts"], client_ip)
            used.add(pkt_id)

            pair = (client_ip, middle_ip)
            pair_counts[pair] += 1
            count = pair_counts[pair]

            matches += 1
            delay_us = int(min_diff * 1_000_000)

            # Mostra contagem - pares com count alto são mais confiáveis
            print(f"\n[MATCH {matches}] Δ={delay_us}µs count={count}")
            print(f"  Cliente: {client_ip} -> Guard:{guard_port} -> Middle: {middle_ip}:{middle_port}")
            save(matches, client_ip, middle_ip)

    # Limpa used e buffers antigos
    stale = {k for k in used if ts - k[0] > 5.0}
    used.difference_update(stale)

    for buf in list(client_buffers.values()):
        while buf and ts - buf[0]["ts"] > 5:
            buf.popleft()

def print_stats():
    print(f"\n=== TOP PARES (Cliente → Middle) ===")
    for (client, middle), count in pair_counts.most_common(10):
        print(f"  {count:4}x  {client} → {middle}")

load_tor_relays()
print(f"\nGuard: {guard_ip}:{guard_port} | Relays: {len(tor_relays)}")
print(f"Janela: 20ms | ratio: 0.8-1.2\n")

try:
    sniff(prn=process_packet, store=False)
except KeyboardInterrupt:
    print(f"\n=== {matches} correlações ===")
    print_stats()
