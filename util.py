import ollama
from scapy.all import rdpcap
import pandas as pd

def generate_embedding(model,prompt):
    return ollama.embeddings(model=model,prompt=prompt)

def extract_packets(pcap_file):
    packets = rdpcap(pcap_file)
    return packets

def get_bytes(packet):
    return bytes(packet)

def get_packet_metadata(packet):
    metadata = {
        'time':float(packet.time),
        'len':len(packet)
    }

    if packet.haslayer('Ethernet'):
        metadata['eth_src'] = packet['Ethernet'].src
        metadata['eth_dst'] = packet['Ethernet'].dst
    else:
        metadata['eth_src'] = metadata['eth_dst'] = ''
    
    if packet.haslayer('IP'):
        metadata['ip_src'] = packet['IP'].src
        metadata['ip_dst'] = packet['IP'].dst
        metadata['ip_proto'] = packet['IP'].proto
    else:
        metadata['ip_src'] = metadata['ip_dst'] = metadata['ip_proto'] = ''

    if packet.haslayer('TCP'):
        metadata['tcp_sport'] = packet['TCP'].sport
        metadata['tcp_dport'] = packet['TCP'].dport
        metadata['tcp_flags'] = packet['TCP'].flags
    else:
        metadata['tcp_sport'] = metadata['tcp_dport'] = metadata['tcp_flags'] = ''   

    if packet.haslayer('UDP'):
        metadata['udp_sport'] = packet['UDP'].sport
        metadata['udp_dport'] = packet['UDP'].dport
    else:
        metadata['udp_sport'] = metadata['udp_dport'] = ''

    return metadata

def get_packet_summary(packet):
    return packet.summary()

def get_data_from_file(pcap_file):
    data = {
        'metadata':[],
        'summary':[],
        'raw':[]
    }
    for packet in extract_packets(pcap_file):
        data['metadata'].append(get_packet_metadata(packet))
        data['summary'].append(get_packet_summary(packet))
        data['raw'].append(get_bytes(packet))

    return data

def embed_df(df,model):
    new_metadata = [generate_embedding(model=model,prompt=x) for x in df['metadata']]
    new_summary = [generate_embedding(model=model,prompt=x) for x in df['summary']]
    new_raw = [generate_embedding(model=model,prompt=x) for x in df['raw']]
    new_df = pd.DataFrame([new_metadata,new_summary,new_raw],columns=['metadata','summary','raw'])
    return new_df
