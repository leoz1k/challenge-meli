from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from collections import defaultdict, Counter
import csv
import os

# Variaveis para armazenar estatísticas e dados coletados
protocolos = defaultdict(int)
trafego_por_origem = Counter()
trafego_por_destino = Counter()
dados_para_csv = []

LIMITE_PACOTES = 20

def processar_pacote(pacote):
    if IP in pacote:
        ip_origem = pacote[IP].src
        ip_destino = pacote[IP].dst
        tamanho = len(pacote)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if TCP in pacote:
            protocolo = "TCP"
        elif UDP in pacote:
            protocolo = "UDP"
        else:
            protocolo = str(pacote[IP].proto)

        # Atualizar contadores, realizar o controle dos pacotes coletados..x
        protocolos[protocolo] += 1
        trafego_por_origem[ip_origem] += 1
        trafego_por_destino[ip_destino] += 1

        print(f"[{timestamp}] Origem: {ip_origem} -> Destino: {ip_destino} | Protocolo: {protocolo} | Tamanho: {tamanho} bytes")

        # Salva no buffer
        dados_para_csv.append([timestamp, ip_origem, ip_destino, protocolo, tamanho])

        # Se atingiu o limite, para a captura
        if len(dados_para_csv) >= LIMITE_PACOTES:
            return True  # Faz o sniff parar

def salvar_em_csv():
    caminho = "/home/leonardodylan/Documentos"
    nome_arquivo = os.path.join(caminho, "trafego_capturado.csv")

    with open(nome_arquivo, mode="w", newline="") as arquivo:
        writer = csv.writer(arquivo)
        writer.writerow(["Timestamp", "IP Origem", "IP Destino", "Protocolo", "Tamanho (bytes)"])
        writer.writerows(dados_para_csv)

    print(f"\n📁 Arquivo salvo com sucesso em: {nome_arquivo}")

def exibir_estatisticas():
    print("\n=== Estatísticas de Trafego ===")
    print(f"Total de pacotes capturados: {len(dados_para_csv)}")

    print("\nPacotes por protocolo:")
    for protocolo, contagem in protocolos.items():
        print(f"  {protocolo}: {contagem}")

    print("\nTop 5 IPs de origem:")
    for ip, count in trafego_por_origem.most_common(5):
        print(f"  {ip}: {count} pacotes")

    print("\nTop 5 IPs de destino:")
    for ip, count in trafego_por_destino.most_common(5):
        print(f"  {ip}: {count} pacotes")

# Interface de rede
interface = "eno1"  # Altere conforme sua interface

print(f"[*] Capturando {LIMITE_PACOTES} pacotes na interface: {interface}...")

# Captura com limite
sniff(iface=interface, prn=processar_pacote, store=False, stop_filter=lambda x: len(dados_para_csv) >= LIMITE_PACOTES)

# Pós-captura
exibir_estatisticas()
salvar_em_csv()
