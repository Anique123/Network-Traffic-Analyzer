Packet Classifier using Machine Learning
This is a Python script that captures network traffic and classifies packets based on their port numbers using machine learning. The capture will be used in a SIEM tool to analyze the traffic captured. The script uses the Scapy library for packet capture and feature extraction, and the Scikit-learn library for machine learning.

Installation
To install the required dependencies, run the following command:

Copy code
pip install scapy scikit-learn pandas
Usage
To run the script, use the following command:

Copy code
sudo python analyzer.py
The script will capture network traffic for a default of 10 seconds on the eth0 interface, extract features from TCP packets, and train a decision tree classifier using the extracted features and class labels based on the port numbers. After training, the script will enter an infinite loop and classify incoming packets in real-time.

Customization
You can customize the script by changing the following variables:

capture_time: The duration of packet capture in seconds (default is 10 seconds)
iface: The network interface to capture packets from (default is eth0)
class_labels: A dictionary of port numbers and their corresponding class labels
feature_names: A list of feature names to use for training the classifier
License
This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgments
Scapy library: https://scapy.net/
Scikit-learn library: https://scikit-learn.org/
Inspired by: https://www.analyticsvidhya.com/blog/2020/07/packet-sniffing-using-scapy/
etc.
