from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from collections import defaultdict, Counter

# Estatísticas
total_pacotes = 0
protocolos = defaultdict(int)
trafego_por_origem = Counter()
trafego_por_destino = Counter()

def processar_pacote(pacote):
    global total_pacotes

    if IP in pacote:
        total_pacotes += 1
        ip_origem = pacote[IP].src
        ip_destino = pacote[IP].dst
        tamanho = len(pacote)

        # Contar por IP
        trafego_por_origem[ip_origem] += 1
        trafego_por_destino[ip_destino] += 1

        # Identificar protocolo
        if TCP in pacote:
            protocolo = "TCP"
        elif UDP in pacote:
            protocolo = "UDP"
        else:
            protocolo = str(pacote[IP].proto)

        protocolos[protocolo] += 1

        print(f"[{datetime.now()}] Origem: {ip_origem} -> Destino: {ip_destino} | Protocolo: {protocolo} | Tamanho: {tamanho} bytes")

def exibir_estatisticas():
    print("\n=== Estatísticas de Tráfego ===")
    print(f"Total de pacotes capturados: {total_pacotes}")

    print("\nPacotes por protocolo:")
    for protocolo, contagem in protocolos.items():
        print(f"  {protocolo}: {contagem}")

    print("\nTop 5 IPs de origem:")
    for ip, count in trafego_por_origem.most_common(5):
        print(f"  {ip}: {count} pacotes")

    print("\nTop 5 IPs de destino:")
    for ip, count in trafego_por_destino.most_common(5):
        print(f"  {ip}: {count} pacotes")

# Interface de rede (substitua pela sua)
interface = "eno1"

print(f"[*] Capturando pacotes na interface: {interface} (pressione Ctrl+C para encerrar)...")

try:
    sniff(iface=interface, prn=processar_pacote, store=False)
except KeyboardInterrupt:
    exibir_estatisticas()
