from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
import joblib
from datetime import datetime, timedelta
import numpy as np
import warnings
from sklearn.utils import validation  # Import the specific module

# Suppress the UserWarning from sklearn.utils.validation
warnings.filterwarnings("ignore", category=UserWarning, module=validation.__name__)

#=== Configuration ===
MODEL_PATH = '/home/jayesh-_-/Major/nids_model.joblib'
INTERFACE = 'wlo1'  # or 'wlan0' depending on your setup
ATTACK_THRESHOLD = 0.8  # Probability threshold to consider a packet as an attack
MONITOR_DURATION = timedelta(minutes=1)

IMPORTANT_FEATURES = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'logged_in', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'same_srv_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate'
]

#=== Load Model ===
print("🔄 Loading model...")
try:
    model = joblib.load(MODEL_PATH)
    print("✅ Model loaded.\n")
except FileNotFoundError:
    print(f"❌ Error: Model file not found at {MODEL_PATH}")
    exit()
except Exception as e:
    print(f"❌ Error loading model: {e}")
    exit()

#=== Packet Processing State ===
packet_window = []
WINDOW_SIZE = 50  # Number of packets to consider for context
attack_detected_within_minute = False
start_time = None

#=== Helper Functions ===
def extract_features(packet):
    protocol = 'tcp' if TCP in packet else 'udp' if UDP in packet else 'other'
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet.sport if hasattr(packet, 'sport') else 0
    dst_port = packet.dport if hasattr(packet, 'dport') else 0
    length = len(packet)
    # Feature assumptions
    service = 'http' if dst_port == 80 else 'other'
    flag = 'SF' if TCP in packet and packet[TCP].flags == 'PA' else 'S0'
    timestamp = datetime.now()
    return {
        'timestamp': timestamp,
        'protocol_type': protocol,
        'service': service,
        'flag': flag,
        'src_bytes': src_port,  # Just placeholders; replace with actual byte counts if needed
        'dst_bytes': dst_port,
        'duration': 0,  # Could be calculated using timestamps across flows
        'src_ip': src_ip,
        'dst_ip': dst_ip
    }

def compute_aggregates(packet_window):
    count = len(packet_window)
    srv_count = len(set(p['service'] for p in packet_window))
    serror_rate = sum(1 for p in packet_window if p['flag'] == 'S0') / count if count else 0
    srv_serror_rate = serror_rate
    same_srv_rate = sum(1 for p in packet_window if p['service'] == 'http') / count if count else 0
    dst_host_count = count
    dst_host_srv_count = srv_count
    dst_host_same_srv_rate = same_srv_rate
    dst_host_diff_srv_rate = 1 - same_srv_rate
    dst_host_serror_rate = serror_rate
    dst_host_srv_serror_rate = srv_serror_rate
    return {
        'logged_in': 0,
        'count': count,
        'srv_count': srv_count,
        'serror_rate': serror_rate,
        'srv_serror_rate': serror_rate,
        'same_srv_rate': same_srv_rate,
        'dst_host_count': dst_host_count,
        'dst_host_srv_count': dst_host_srv_count,
        'dst_host_same_srv_rate': dst_host_same_srv_rate,
        'dst_host_diff_srv_rate': dst_host_diff_srv_rate,
        'dst_host_serror_rate': dst_host_serror_rate,
        'dst_host_srv_serror_rate': dst_host_srv_serror_rate
    }

#=== Real-Time Prediction Handler ===
def process_packet(packet):
    global attack_detected_within_minute, start_time

    if IP not in packet:
        return

    if start_time is None:
        start_time = datetime.now()

    features = extract_features(packet)
    packet_window.append(features)
    if len(packet_window) > WINDOW_SIZE:
        packet_window.pop(0)

    if len(packet_window) < 10:
        return  # Not enough data yet

    agg = compute_aggregates(packet_window)
    feature_vector = {**features, **agg}
    input_df = pd.DataFrame([feature_vector]).reindex(columns=IMPORTANT_FEATURES, fill_value=0)

    proba = model.predict_proba(input_df)[0]
    attack_probability = proba[1]

    if attack_probability >= ATTACK_THRESHOLD:
        prediction = 1
        label = "Attack"
        print(f"🚨 ATTACK DETECTED (Probability: {attack_probability*100:.2f}%)")
        print(f"🧾 Src: {features['src_ip']} → Dst: {features['dst_ip']} | Protocol: {features['protocol_type']}\n")
        attack_detected_within_minute = True

#=== Start Sniffing ===
print(f"🚀 Starting real-time NIDS on interface: {INTERFACE} for {MONITOR_DURATION}")
sniff(iface=INTERFACE, prn=process_packet, store=False, timeout=int(MONITOR_DURATION.total_seconds()))

print("🛑 Sniffing stopped.")
if not attack_detected_within_minute:
    print(f"✅ No attack packets detected within the {MONITOR_DURATION}.")
else:
    print("⚠️ Attack packets were detected during the monitoring period (see above for details).")