import pandas as pd
import numpy as np
import joblib

from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


# =========================================================
# NSL-KDD Column Names
# =========================================================
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files',
    'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate',
    'label',
    'difficulty'
]

# =========================================================
# Load Dataset
# =========================================================
train_data = pd.read_csv(
    'data/Train.txt',
    names=columns
)

test_data = pd.read_csv(
    'data/Test.txt',
    names=columns
)

# =========================================================
# Remove Difficulty Column
# =========================================================
train_data.drop('difficulty', axis=1, inplace=True)
test_data.drop('difficulty', axis=1, inplace=True)

print("Training Data Shape:", train_data.shape)
print("Testing Data Shape:", test_data.shape)

# =========================================================
# Attack Category Mapping
# =========================================================
attack_mapping = {

    # ---------------- Normal ----------------
    'normal': 'Normal',

    # ---------------- DOS ----------------
    'back': 'DOS',
    'land': 'DOS',
    'neptune': 'DOS',
    'pod': 'DOS',
    'smurf': 'DOS',
    'teardrop': 'DOS',
    'apache2': 'DOS',
    'udpstorm': 'DOS',
    'processtable': 'DOS',
    'mailbomb': 'DOS',

    # ---------------- PROBE ----------------
    'ipsweep': 'PROBE',
    'nmap': 'PROBE',
    'portsweep': 'PROBE',
    'satan': 'PROBE',
    'saint': 'PROBE',
    'mscan': 'PROBE',

    # ---------------- R2L ----------------
    'ftp_write': 'R2L',
    'guess_passwd': 'R2L',
    'imap': 'R2L',
    'multihop': 'R2L',
    'phf': 'R2L',
    'spy': 'R2L',
    'warezclient': 'R2L',
    'warezmaster': 'R2L',
    'snmpgetattack': 'R2L',
    'snmpguess': 'R2L',
    'httptunnel': 'R2L',
    'sendmail': 'R2L',
    'named': 'R2L',
    'xlock': 'R2L',
    'xsnoop': 'R2L',
    'worm': 'R2L',

    # ---------------- U2R ----------------
    'buffer_overflow': 'U2R',
    'loadmodule': 'U2R',
    'perl': 'U2R',
    'rootkit': 'U2R',
    'ps': 'U2R',
    'sqlattack': 'U2R',
    'xterm': 'U2R',
}

# =========================================================
# Clean Labels
# =========================================================
train_data['label'] = train_data['label'].astype(str).str.strip()
test_data['label'] = test_data['label'].astype(str).str.strip()

# =========================================================
# Convert Attack Names to Categories
# =========================================================
train_data['label'] = train_data['label'].map(
    lambda x: attack_mapping.get(x, x)
)

test_data['label'] = test_data['label'].map(
    lambda x: attack_mapping.get(x, x)
)

print("\nUnique Labels:")
print(train_data['label'].unique())

# =========================================================
# Encode Categorical Features
# =========================================================
protocol_encoder = LabelEncoder()
service_encoder = LabelEncoder()
flag_encoder = LabelEncoder()

train_data['protocol_type'] = protocol_encoder.fit_transform(
    train_data['protocol_type']
)

test_data['protocol_type'] = protocol_encoder.transform(
    test_data['protocol_type']
)

train_data['service'] = service_encoder.fit_transform(
    train_data['service']
)

test_data['service'] = service_encoder.transform(
    test_data['service']
)

train_data['flag'] = flag_encoder.fit_transform(
    train_data['flag']
)

test_data['flag'] = flag_encoder.transform(
    test_data['flag']
)

# =========================================================
# Encode Output Labels
# =========================================================
label_encoder = LabelEncoder()

train_data['label'] = label_encoder.fit_transform(
    train_data['label']
)

test_data['label'] = label_encoder.transform(
    test_data['label']
)

# =========================================================
# Split Features and Labels
# =========================================================
X_train = train_data.drop('label', axis=1)
y_train = train_data['label']

X_test = test_data.drop('label', axis=1)
y_test = test_data['label']

# =========================================================
# Train Model
# =========================================================
print("\nTraining Model...\n")

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

# =========================================================
# Predictions
# =========================================================
y_pred = model.predict(X_test)

# =========================================================
# Accuracy
# =========================================================
accuracy = accuracy_score(y_test, y_pred)

print("\nAccuracy:", accuracy)

print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))

# =========================================================
# Save Model and Encoders
# =========================================================
joblib.dump(model, 'model.pkl')

joblib.dump(label_encoder, 'label_encoder.pkl')
joblib.dump(protocol_encoder, 'protocol_encoder.pkl')
joblib.dump(service_encoder, 'service_encoder.pkl')
joblib.dump(flag_encoder, 'flag_encoder.pkl')

print("\nModel Saved Successfully!")