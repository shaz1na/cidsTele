from scapy.all import sniff, IP, TCP
import urllib
import urllib2
from collections import defaultdict

#Telegram Bot Info
#Keep this info hidden and PRIVATE
bot_token = 'FROM TELEGRAM AFTER CREATING A CHATBOT'
chat_id = 'FROM TELEGRAM AFTER CREATING A CHATBOT'

def send_alert(message):
    url = 'https://api.telegram.org/bot' + bot_token + '/sendMessage'
    data = urllib.urlencode({'chat_id': chat_id, 'text':message})
    request = urllib2.Request(url,data)
    try:
        urllib2.urlopen(request)
        print("Alert sent: " + message)
    except Exception as e:
        print("Failed to send alert: " + str(e))

#Track number of scan packets per IP
scan_count = defaultdict(lambda: {'syn':0,'ack':0, 'connect':0})
handshake_tracker = defaultdict(set)

def detect_scan(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst

        # Filter: only process packets from IP 192.168.0.170
        if src != "192.168.0.170":
            return

        flags = pkt[TCP].flags
        dport = pkt[TCP].dport
        sport = pkt[TCP].sport
        conn_id = (src, dst, sport, dport)

        # SYN scan
        if flags == 0x02:
            scan_count[src]['syn'] += 1
            handshake_tracker[conn_id].add("SYN")
            if scan_count[src]['syn'] > 10:
                send_alert("!! SYN scan detected from %s" % src)
                scan_count[src]['syn'] = 0

        # ACK scan
        elif flags == 0x10 and "SYN" not in handshake_tracker[conn_id]:
            scan_count[src]['ack'] += 1
            if scan_count[src]['ack'] > 10:
                send_alert("!! ACK scan detected from %s" % src)
                scan_count[src]['ack'] = 0

        # TCP connect scan
        elif flags & 0x10 and "SYN" in handshake_tracker[conn_id]:
            scan_count[src]['connect'] += 1
            if scan_count[src]['connect'] > 10:
                send_alert("!! TCP Connect scan detected from %s" % src)
                scan_count[src]['connect'] = 0
                handshake_tracker.pop(conn_id, None)

#Start sniffing
print("[*] IDS is running. Monitoring suspicious incoming traffic to and from Windows 8.1...")
sniff(filter="tcp",prn=detect_scan, store = 0)
