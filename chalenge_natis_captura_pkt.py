from scapy.all import sniff, IP
from datetime import datetime

def processar_pacote(pacote):
    if IP in pacote:
        ip_origem = pacote[IP].src
        ip_destino = pacote[IP].dst
        protocolo = pacote.proto
        tamanho = len(pacote)

        print(f"[{datetime.now()}] Origem: {ip_origem} -> Destino: {ip_destino} | Protocolo: {protocolo} | Tamanho: {tamanho} bytes")

interface = "eno1"  # <--- Substitua pela sua interface
print(f"[*] Capturando pacotes na interface: {interface}...")
sniff(iface=interface, prn=processar_pacote, store=False)
