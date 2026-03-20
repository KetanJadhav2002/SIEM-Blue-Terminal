import sys
import os
import html
import threading
import psutil
import win32evtlog
import pymysql
import pymysql.cursors
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from scapy.all import sniff, IP, TCP, UDP, ARP, DNS, wrpcap, get_working_if
from datetime import datetime
from waitress import serve

import os
import win32evtlog
from datetime import datetime

def save_logs_to_files():
    """Fetches WinEventLogs and saves them to the Logs folder on logout."""
    log_channels = ['Application', 'Security', 'System', 'Setup']
    
    # Ensure folder exists
    if not os.path.exists('Logs'):
        os.makedirs('Logs')

    for channel in log_channels:
        try:
            # Open the specific Windows Event Log
            handle = win32evtlog.OpenEventLog(None, channel)
            # Read backwards (newest first)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(handle, flags, 0)
            
            file_path = os.path.join('Logs', f"{channel}.log")
            
            with open(file_path, "a", encoding="utf-8") as f:
                f.write(f"\n[!] SESSION LOGOUT ARCHIVE - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 80 + "\n")
                
                # Save the last 100 events from this channel
                for event in events[:100]:
                    timestamp = event.TimeGenerated.Format()
                    event_id = event.EventID
                    source = event.SourceName
                    # Simple format: Time | ID | Source
                    f.write(f"{timestamp} | ID: {event_id} | Source: {source}\n")
                
                f.write("-" * 80 + "\n")
            print(f"[+] Successfully saved {channel}.log")
            
        except Exception as e:
            print(f"[-] Could not save {channel} logs: {e}")


# --- PYINSTALLER PATH HANDLING ---
def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath(os.path.dirname(__file__)), relative_path)

# --- INITIALIZE FLASK ---
app = Flask(__name__, 
            template_folder=resource_path('template'),
            static_folder=resource_path('static'))
app.secret_key = 'siem_blue_ultimate_v4_ketan'

# --- FOLDER SETUP ---
exe_location = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else __file__)
for folder in ['Logs', 'NetPacket', 'Database']:
    path = os.path.join(exe_location, folder)
    if not os.path.exists(path): os.makedirs(path)

# Global State
net_traffic = []
pkt_counter = 0
proto_distribution = {}

# --- Database Connection ---
def get_db():
    return pymysql.connect(
        host="localhost",
        user="Admin",
        password="Admin@123",
        database="SIEM_DB",
        cursorclass=pymysql.cursors.DictCursor
    )

# --- Protocol Shortener for Charts ---
def shorten_proto(name):
    mapping = {"Neighbor Discovery": "ND", "Multicast": "MC", "Discovery": "DSCV", "Listener": "LSTN"}
    for long, short in mapping.items():
        name = name.replace(long, short)
    return name[:22]

# --- Network Sniffer ---
def packet_callback(pkt):
    global pkt_counter, proto_distribution
    pkt_counter += 1
    highest_layer = pkt
    while highest_layer.payload and highest_layer.payload.name not in ['Raw', 'padding']:
        highest_layer = highest_layer.payload
    
    p_name = shorten_proto(highest_layer.name)
    proto_distribution[p_name] = proto_distribution.get(p_name, 0) + 1
    
    data = {
        "No": pkt_counter, 
        "Time": datetime.now().strftime("%H:%M:%S.%f")[:-3], 
        "Source": pkt[IP].src if pkt.haslayer(IP) else (pkt.src if hasattr(pkt, 'src') else "Unknown"), 
        "Destination": pkt[IP].dst if pkt.haslayer(IP) else (pkt.dst if hasattr(pkt, 'dst') else "Unknown"), 
        "Protocol": p_name, 
        "Length": len(pkt), 
        "Info": pkt.summary()
    }
    net_traffic.append(data)
    if len(net_traffic) > 150: net_traffic.pop(0)
    wrpcap(os.path.join(exe_location, "NetPacket", "trafic.pcap"), pkt, append=True)

def start_sniffer():
    try:
        iface = get_working_if().name
        sniff(iface=iface, prn=packet_callback, store=0)
    except:
        sniff(prn=packet_callback, store=0)

threading.Thread(target=start_sniffer, daemon=True).start()

# --- Windows Log Engine ---
def fetch_logs(chan):
    res = []
    try:
        h = win32evtlog.OpenEventLog(None, chan)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(h, flags, 0)
        for e in events[:400]:
            res.append({
                "EventID": str(e.EventID & 0xFFFF),
                "Timestamp": e.TimeGenerated.Format(),
                "Channel": chan,
                "Source": e.SourceName
            })
    except: pass
    return res

# --- Routes ---
@app.route('/')
def login(): return render_template('login.html')

@app.route('/auth', methods=['POST'])
def auth():
    u, p = html.escape(request.form.get('username', '')), html.escape(request.form.get('password', ''))
    try:
        db = get_db()
        with db.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username=%s AND password=%s", (u, p))
            res = cursor.fetchone()
        db.close()
        if res:
            session['user'] = u
            return redirect(url_for('dashboard'))
    except Exception as e: print(f"DB Auth Error: {e}")
    return "Invalid Credentials"

@app.route('/dashboard')
def dashboard():
    if 'user' not in session: return redirect(url_for('login'))
    return render_template('layout.html')

@app.route('/api/logs')
def api_logs():
    q = request.args.get('q', '').strip()
    all_l = fetch_logs("System") + fetch_logs("Security") + fetch_logs("Application") + fetch_logs("Setup")
    if q and '=' in q:
        try:
            key_part, val_part = q.split('=', 1)
            search_key = key_part.strip().lower()
            # FIX: Strip quotes for Channel="Security"
            search_val = val_part.strip().strip('"').strip("'").lower()
            key_map = {"eventid": "EventID", "timestamp": "Timestamp", "channel": "Channel", "source": "Source"}
            target_key = key_map.get(search_key, search_key)
            return jsonify([l for l in all_l if str(l.get(target_key, '')).lower() == search_val])
        except: pass
    return jsonify(all_l)

@app.route('/api/stats')
def api_stats():
    return jsonify({
        "cpu": psutil.cpu_percent(interval=0.1),
        "ram": {"used": psutil.virtual_memory().percent, "free": 100 - psutil.virtual_memory().percent},
        "disk": {"used": psutil.disk_usage('/').percent, "free": 100 - psutil.disk_usage('/').percent},
        "network_proto": proto_distribution
    })

@app.route('/api/process')
def api_proc():
    procs = []
    cores = psutil.cpu_count() or 1
    for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            p_info = p.info
            p_info['cpu_percent'] = round(p_info['cpu_percent'] / cores, 2)
            procs.append(p_info)
        except: pass
    procs.sort(key=lambda x: x['cpu_percent'], reverse=True)
    return jsonify(procs)

@app.route('/api/network')
def api_net():
    q = request.args.get('q', '').lower()
    return jsonify([n for n in net_traffic if q in n['Source'].lower() or q in n['Destination'].lower()] if q else net_traffic)

@app.route('/logout')
def logout():
    save_logs_to_files()
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    print(f"SIEM-Blue Hosted at : http://127.0.0.1:12345")
    serve(app, host='127.0.0.1', port=12345, threads=12)
