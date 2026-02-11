from scapy.all import sniff, TCP, IP
from datetime import datetime
from collections import deque
import sys
import socket
import json
import sys

exitNodePort = 9001
MonitorPort = 443
exit_node_ip = "" # IP PUBLICO EXIT NODE

# Buffers com LIMITE (não crescem infinito)
tor_buffer = deque(maxlen=10000)  # máximo 10k pacotes
used_tor = deque(maxlen=5000)     # máximo 5k usados
dns_cache = {}
matches = 0
packets_processed = 0


def save(matches, middle_ip, site_ip, reversedns):
    with open("found.log", 'a') as f:
        f.write(json.dumps({"id": matches, "middle_ip": middle_ip, "site_id": site_ip, 'dnsre': reversedns ,"data": str(datetime.now())}) + "\n")


def reverse_dns(ip):
    if ip in dns_cache:
        return dns_cache[ip]
    try:
        # Timeout de 1 segundo (não trava)
        socket.setdefaulttimeout(1.0)
        domain = socket.gethostbyaddr(ip)[0].lower()
        dns_cache[ip] = domain
        return domain
    except:
        dns_cache[ip] = ip
        return ip
    finally:
        socket.setdefaulttimeout(None)

def process_packet(pkt):
    global matches, packets_processed
    packets_processed += 1
    
    if IP not in pkt or TCP not in pkt:
        return
    
    ip_layer = pkt[IP]
    tcp_layer = pkt[TCP]
    ts = float(pkt.time)
    dt = datetime.utcfromtimestamp(ts)
    time_str = dt.strftime('%H:%M:%S.') + f"{int((ts % 1) * 1_000_000):06d}"
    pkt_len = len(pkt)
    
    # Porta 9001
    if (tcp_layer.dport == exitNodePort or tcp_layer.sport == exitNodePort):
        if ip_layer.dst == exit_node_ip:
            if pkt_len >= 100:
                tor_buffer.append({
                    "ts": ts,
                    "len": pkt_len,
                    "middle_ip": ip_layer.src
                })
    
    # Porta 443
    elif (tcp_layer.dport == MonitorPort or tcp_layer.sport == MonitorPort):
        if ip_layer.src == exit_node_ip:
            dest_ip = ip_layer.dst
            
            if pkt_len < 100:
                return
            
            best_match = None
            best_score = float('inf')
            
            # Procura só nos últimos 200 pacotes (mais rápido)
            for tor_pkt in list(tor_buffer)[-200:]:
                pkt_id = (tor_pkt["ts"], tor_pkt["middle_ip"])
                if pkt_id in used_tor:
                    continue
                
                time_diff = ts - tor_pkt["ts"]
                
                if 0 < time_diff <= 0.1:
                    size_ratio = tor_pkt["len"] / pkt_len
                    
                    if pkt_len > 1000:
                        ratio_ok = 0.8 <= size_ratio <= 1.2
                    elif pkt_len > 500:
                        ratio_ok = 0.7 <= size_ratio <= 1.5
                    elif pkt_len > 200:
                        ratio_ok = 0.5 <= size_ratio <= 5.0
                    else:
                        ratio_ok = 0.3 <= size_ratio <= 10.0
                    
                    if ratio_ok:
                        score = time_diff * 1000 + abs(1.0 - size_ratio) * 10
                        
                        if score < best_score:
                            best_score = score
                            best_match = tor_pkt
            
            if best_match:
                matches += 1
                delay_ms = int((ts - best_match["ts"]) * 1000)
                ratio = best_match["len"] / pkt_len
                domain = reverse_dns(dest_ip)
                
                print(f"\n[MATCH {matches}] Δ={delay_ms}ms ({best_match['len']}→{pkt_len}b) ratio={ratio:.2f}")
                print(f"Middle: {best_match['middle_ip']} -> Exit: {exit_node_ip} -> Site: {dest_ip} ({domain})")
                save(matches, best_match['middle_ip'], dest_ip, domain)

                pkt_id = (best_match["ts"], best_match["middle_ip"])
                used_tor.append(pkt_id)  # deque auto-remove os velhos
    
    # Info de progresso a cada 5000 pacotes
    if packets_processed % 5000 == 0:
        print(f"[INFO] Processados: {packets_processed}, Matches: {matches}, Buffer: {len(tor_buffer)}", file=sys.stderr)

print(f"Correlação otimizada (sem vazamento de memória)\n")

try:
    sniff(filter=f"tcp port {exitNodePort} or tcp port {MonitorPort}", prn=process_packet, store=False)
except KeyboardInterrupt:
    print(f"\n=== {matches} correlações em {packets_processed} pacotes ===")
