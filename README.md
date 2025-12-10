# Network Intrusion Detection System (NIDS)

A machine learning-based Network Intrusion Detection System that uses LightGBM to detect malicious network traffic in real-time. This project provides both offline batch processing and live network monitoring capabilities for personal and small-office network security.

## 🎯 Features

- **Machine Learning-Based Detection**: LightGBM classifier trained on KDD Cup 1999 dataset
- **Real-Time Monitoring**: Live packet capture and analysis using Scapy
- **Batch Processing**: Analyze network traffic data from files
- **High Accuracy**: 78% overall accuracy with 97% precision for attack detection
- **Feature Engineering**: 18 carefully selected network features for optimal detection
- **Easy Deployment**: Simple setup with minimal dependencies

## 📋 Requirements

- Python 3.8+
- Linux/macOS (for real-time packet capture)
- Root/Administrator privileges (for live packet sniffing)
- Network interface access

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/1kiloghoul7/NIDS.git
   cd NIDS
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Download the KDD Cup 1999 dataset**
   - Download `KDDTrain+.txt` and `KDDTest+.txt` from the [KDD Cup 1999 website](http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html)
   - Place both files in the project root directory

## 📁 Project Structure

```
NIDS/
├── Model.ipynb              # Jupyter notebook for model training
├── trial.py                 # Real-time network monitoring script
├── run_nids.sh              # Shell script to run the NIDS
├── requirements.txt         # Python dependencies
├── nids_model.joblib        # Trained model file (generated after training)
├── README.md                # This file
└── .venv/                   # Virtual environment (created during setup)
```

## 🔧 Usage

### 1. Training the Model

Open and run `Model.ipynb` in Jupyter Notebook:

```bash
jupyter notebook Model.ipynb
```

The notebook will:
- Load and preprocess the KDD Cup 1999 dataset
- Train a LightGBM classifier with 18 selected features
- Evaluate the model on test data
- Save the trained model as `nids_model.joblib`

**Expected Results:**
- Overall Accuracy: ~78%
- Attack Detection Precision: ~97%
- Normal Traffic Precision: ~66%

### 2. Batch Prediction

The notebook includes functionality to process batch inputs from `input_data.txt`:

1. Create an `input_data.txt` file with comma-separated values (one record per line)
2. Each line should contain 18 features in this order:
   ```
   duration, protocol_type, service, flag, src_bytes, dst_bytes, 
   logged_in, count, srv_count, serror_rate, srv_serror_rate, 
   same_srv_rate, dst_host_count, dst_host_srv_count, 
   dst_host_same_srv_rate, dst_host_diff_srv_rate, 
   dst_host_serror_rate, dst_host_srv_serror_rate
   ```
3. Run the batch prediction cell in the notebook

**Example input:**
```
0,tcp,http,SF,0,0,0,123,6,1.00,1.00,0.05,255,26,0.10,0.05,1.00,1.00
0,tcp,http,SF,232,8153,1,5,5,0.20,0.20,1.00,30,255,0.90,0.10,0.00,0.00
```

### 3. Real-Time Network Monitoring

**Important**: Real-time monitoring requires root/administrator privileges.

1. **Update configuration** in `trial.py`:
   ```python
   MODEL_PATH = '/path/to/nids_model.joblib'  # Update to your model path
   INTERFACE = 'wlo1'  # Change to your network interface (e.g., 'eth0', 'wlan0')
   ATTACK_THRESHOLD = 0.8  # Adjust threshold (0.0-1.0)
   MONITOR_DURATION = timedelta(minutes=1)  # Set monitoring duration
   ```

2. **Run the monitoring script**:
   ```bash
   sudo python trial.py
   ```
   
   Or use the provided shell script:
   ```bash
   chmod +x run_nids.sh
   sudo ./run_nids.sh
   ```

The system will:
- Capture live network packets from the specified interface
- Extract features using a sliding window (50 packets)
- Classify each packet as Normal or Attack
- Display alerts when attack probability exceeds the threshold

**Example Output:**
```
🔄 Loading model...
✅ Model loaded.

🚀 Starting real-time NIDS on interface: wlo1 for 0:01:00
🚨 ATTACK DETECTED (Probability: 99.98%)
🧾 Src: 192.168.1.100 → Dst: 10.0.0.5 | Protocol: tcp

🛑 Sniffing stopped.
⚠️ Attack packets were detected during the monitoring period.
```

## ⚙️ Configuration

### Model Parameters

Edit the LightGBM parameters in `Model.ipynb`:
```python
lgb.LGBMClassifier(
    random_state=42,
    n_estimators=100,      # Number of boosting iterations
    learning_rate=0.1,      # Learning rate
    max_depth=10,          # Maximum tree depth
    n_jobs=-1              # Use all CPU cores
)
```

### Real-Time Monitoring Parameters

Edit `trial.py`:
- `WINDOW_SIZE`: Number of packets in sliding window (default: 50)
- `ATTACK_THRESHOLD`: Probability threshold for attack alerts (default: 0.8)
- `MONITOR_DURATION`: How long to monitor (default: 1 minute)

## 📊 Selected Features

The model uses 18 features selected for optimal detection:

**Basic Features:**
- `duration`, `protocol_type`, `service`, `flag`
- `src_bytes`, `dst_bytes`, `logged_in`

**Connection Statistics:**
- `count`, `srv_count`
- `serror_rate`, `srv_serror_rate`
- `same_srv_rate`

**Host-Based Features:**
- `dst_host_count`, `dst_host_srv_count`
- `dst_host_same_srv_rate`, `dst_host_diff_srv_rate`
- `dst_host_serror_rate`, `dst_host_srv_serror_rate`

## 🐛 Troubleshooting

### Model File Not Found
- Ensure `nids_model.joblib` exists in the specified path
- Run the training notebook first to generate the model

### Permission Denied (Real-Time Monitoring)
- Use `sudo` to run the monitoring script
- Ensure your user has network interface access permissions

### Interface Not Found
- List available interfaces: `ip link show` or `ifconfig`
- Update `INTERFACE` in `trial.py` with the correct interface name

### Import Errors
- Activate the virtual environment: `source .venv/bin/activate`
- Reinstall dependencies: `pip install -r requirements.txt`

## 📈 Performance Metrics

On KDDTest+ dataset:
- **Overall Accuracy**: 78%
- **Attack Detection**: 
  - Precision: 97%
  - Recall: 63%
  - F1-Score: 76%
- **Normal Traffic**:
  - Precision: 66%
  - Recall: 97%
  - F1-Score: 79%

## 🔒 Security Note

This tool is designed for personal network security monitoring. For production environments:
- Consider additional security measures
- Implement proper logging and alerting systems
- Use encrypted communication channels
- Follow your organization's security policies

## 📚 References

- KDD Cup 1999 Dataset: [UCI Machine Learning Repository](http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html)
- LightGBM Documentation: [Microsoft LightGBM](https://lightgbm.readthedocs.io/)
- Scapy Documentation: [Scapy](https://scapy.net/)
