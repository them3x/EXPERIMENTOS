import paramiko
import time
import json
from datetime import datetime

guard_ip = ""
exit_ip = ""
log_path = "/root/mtim/found.log" # pasta dos logs gerados
ssh_key = "/home/messias/.ssh/id_rsa"

def parse_dt(s):
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S.%f")

def iter_remote_lines(ip, path):
    while True:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username="root", key_filename=ssh_key, timeout=20)
            _, stdout, _ = ssh.exec_command(f"cat {path}")
            for line in stdout:
                yield line.rstrip('\n')
            ssh.close()
            break
        except Exception as e:
            print(f"[ERRO] {ip}: {e}")

seen_guard = set()
seen_exit = set()
guard_data = {}
exit_data = {}
founds = []
shown = set()

while True:
    for line in iter_remote_lines(guard_ip, log_path):
        try:
            j = json.loads(line)
            if j['id'] in seen_guard:
                continue
            seen_guard.add(j['id'])
            middle = j['middle']
            if middle not in guard_data:
                guard_data[middle] = []
            guard_data[middle].append({"id": j['id'], "client": j['client'], "data": j['data']})
        except:
            pass

    for line in iter_remote_lines(exit_ip, log_path):
        try:
            j = json.loads(line)
            if j['id'] in seen_exit:
                continue
            seen_exit.add(j['id'])
            middle = j['middle_ip']
            if middle not in exit_data:
                exit_data[middle] = []
            exit_data[middle].append({"id": j['id'], "site": j['site_id'], "data": j['data'], "dns": j['dnsre']})
        except:
            pass

    for middle_ip in guard_data:
        if middle_ip not in exit_data:
            continue
        
        for g in guard_data[middle_ip]:
            for e in exit_data[middle_ip]:
                corr_id = (g['id'], e['id'])
                if corr_id in shown:
                    continue
                shown.add(corr_id)
                
                # Compara só minutos e segundos (ignora diferença de fuso)
                diff = abs((parse_dt(g['data']) - parse_dt(e['data'])).total_seconds()) % 3600
                if diff > 120:
                    continue
                
                check = g['client'] + g['data'].split('.')[0] + e['data'].split('.')[0]
                if check not in founds:
                    founds.append(check)
                    print(f"{g['data']} | C: {g['client']} -> M: {middle_ip} -> S: {e['site']} {e['dns']}")

    time.sleep(5)

