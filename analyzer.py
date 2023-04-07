from scapy.all import * 
import pandas as pd

def capture_traffic(capture_time, iface):
    capture_time = 15
    iface = "en0"
    cap = sniff(iface=iface, timeout=capture_time)
    return cap

def extract_features(packet):
    features = []
    features.append(packet[IP].src)
    features.append(packet[TCP].sport)
    features.append(packet[IP].dst)
    features.append(packet[TCP].dport)
    features.append(packet[TCP].payload.load)
    features.append(packet.time)
    return features

def preparing_training_data(pac):
    dataset = []
    class_labels = {
        'HTTP': 0,
        'HTTPS': 1,
        'DNS': 2,
        'ARP': 3
    }
    for packet in pac:
        if packet.haslayer(TCP):
            features = extract_features(packet)
            class_label = class_labels.get(packet[TCP].payload.name, -1)
            if class_label != -1:
                dataset.append(features + [class_label])

    coloum_names = ["Src. IP", "Src. Port", "Dst. IP", "Dst. Port", "Payload", "Time", "Class"]
    df = pd.DataFrame(dataset, columns=coloum_names)

    # Split into Training and Validation Sets
    X = df.drop('Class Label', axis=1)  # Features
    y = df['Class Label']  # Class labels
    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

if __name__ == "__main__":
    pass