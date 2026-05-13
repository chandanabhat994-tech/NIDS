import numpy as np
import joblib

from flask import Flask, render_template, request

# =========================================================
# Load Saved Model and Encoders
# =========================================================
model = joblib.load('model.pkl')

protocol_encoder = joblib.load('protocol_encoder.pkl')
service_encoder = joblib.load('service_encoder.pkl')
flag_encoder = joblib.load('flag_encoder.pkl')

label_encoder = joblib.load('label_encoder.pkl')

# =========================================================
# Flask App
# =========================================================
app = Flask(__name__)

# =========================================================
# Home Page
# =========================================================
@app.route('/')
def home():
    return render_template('index.html')

# =========================================================
# Prediction Route
# =========================================================
@app.route('/predict', methods=['POST'])
def predict():

    try:

        # =================================================
        # Get Form Data
        # =================================================
        duration = float(request.form['duration'])

        protocol_type = request.form['protocol_type']
        service = request.form['service']
        flag = request.form['flag']

        src_bytes = float(request.form['src_bytes'])
        dst_bytes = float(request.form['dst_bytes'])

        count = float(request.form['count'])
        srv_count = float(request.form['srv_count'])

        serror_rate = float(request.form['serror_rate'])
        same_srv_rate = float(request.form['same_srv_rate'])

        dst_host_count = float(request.form['dst_host_count'])
        dst_host_srv_count = float(request.form['dst_host_srv_count'])

        # =================================================
        # Encode Categorical Values
        # =================================================
        protocol_type = protocol_encoder.transform([protocol_type])[0]
        service = service_encoder.transform([service])[0]
        flag = flag_encoder.transform([flag])[0]

        # =================================================
        # Feature Array
        # =================================================
        features = np.array([[
    duration,                 # duration
    protocol_type,            # protocol_type
    service,                  # service
    flag,                     # flag
    src_bytes,                # src_bytes
    dst_bytes,                # dst_bytes

    0,                        # land
    0,                        # wrong_fragment
    0,                        # urgent
    0,                        # hot
    0,                        # num_failed_logins
    1,                        # logged_in
    0,                        # num_compromised
    0,                        # root_shell
    0,                        # su_attempted
    0,                        # num_root
    0,                        # num_file_creations
    0,                        # num_shells
    0,                        # num_access_files
    0,                        # num_outbound_cmds
    0,                        # is_host_login
    0,                        # is_guest_login

    count,                    # count
    srv_count,                # srv_count
    serror_rate,              # serror_rate

    serror_rate,              # srv_serror_rate
    0.0,                      # rerror_rate
    0.0,                      # srv_rerror_rate
    same_srv_rate,            # same_srv_rate
    0.0,                      # diff_srv_rate
    0.0,                      # srv_diff_host_rate

    dst_host_count,           # dst_host_count
    dst_host_srv_count,       # dst_host_srv_count

    same_srv_rate,            # dst_host_same_srv_rate
    0.0,                      # dst_host_diff_srv_rate
    0.0,                      # dst_host_same_src_port_rate
    0.0,                      # dst_host_srv_diff_host_rate

    serror_rate,              # dst_host_serror_rate
    serror_rate,              # dst_host_srv_serror_rate

    0.0,                      # dst_host_rerror_rate
    0.0                       # dst_host_srv_rerror_rate
]])

        # =================================================
        # Prediction
        # =================================================
        prediction = model.predict(features)

        prediction_label = label_encoder.inverse_transform(
            prediction
        )[0]

        return render_template(
            'prediction.html',
            prediction_text=f'Attack Type: {prediction_label}'
        )

    except Exception as e:

        return render_template(
            'prediction.html',
            prediction_text=f'Error: {str(e)}'
        )

# =========================================================
# Run App
# =========================================================
if __name__ == "__main__":
    app.run(debug=True)