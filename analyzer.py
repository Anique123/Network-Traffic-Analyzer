from scapy.all import * 
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Defining interface and time for capturing of traffic
def capture_traffic(iface, capture_time):
    cap = sniff(iface=iface, timeout=capture_time)
    return cap

# Defining the features that should be analyzed from the capture
def extract_features(packet):
    features = []
    # Possible to customize
    features.append(packet[IP].src)
    features.append(packet[TCP].sport)
    features.append(packet[IP].dst)
    features.append(packet[TCP].dport)
    #features.append(str(packet[TCP].payload.load))
    features.append(pd.to_datetime(packet.time, unit= "s"))
    return features

# Normal Capture without ML prep
def packet_filtering(cap):    
    dataset = []
    for packet in cap:
        if packet.haslayer(TCP):
            features = extract_features(packet)
            dataset.append(features)
    coloum_names = ["Src. IP", "Src. Port", "Dst. IP", "Dst. Port", "Time"]
    df = pd.DataFrame(dataset, columns=coloum_names)
    #print(df)
    return df

if __name__ == "__main__":
    #Defining variables for sniff
    capture_time = 10
    iface = "en0"

    # Running methods
    cap = capture_traffic(iface, capture_time)
    df = packet_filtering(cap)
    
    print(df)