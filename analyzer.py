from scapy.all import * 

def extract_features(packet):
    features = []
    features.append(packet[IP].src)
    features.append(packet[IP].dst)
    features.append(packet[TCP].sport)
    features.append(packet[TCP].dport)
    features.append(packet[TCP].payload.load)
    features.append(packet.time)
    return features


def capture_traffic(capture_time, iface):
    capture_time = 15
    iface = "en0"
    cap = sniff(iface=iface, timeout=capture_time)
    return cap

def preparing_training_data():
    class_labels = {
        'HTTP': 0,
        'HTTPS': 1,
        'DNS': 2,
        'ARP': 3
    }


if __name__ == "__main__":
    main()