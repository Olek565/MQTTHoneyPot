import paho.mqtt.client as mqtt
import logging
import re
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime, timedelta
from scapy.all import sniff, IP, TCP, Ether, Raw, load_contrib, get_if_list, IPv6
# from scapy.layers.mqtt import MQTT, MQTTSubscribe
from scapy.contrib.mqtt import MQTT
import scapy.all as scapy
from collections import defaultdict, deque
import struct
import random
import threading
from geoip2.database import Reader
import time
import json



def get_script_directory() -> str:
    """
    Returns the directory path where the script is located.
    """
    try:
        return os.path.dirname(os.path.realpath(__file__))
    except OSError as oe:
        logging.error(f"OSError: {oe}")
        raise
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        raise


def setup_logging(log_dir="mqtt_honeypot_logs",
                  log_file="mqtt_honeypot.log",
                  max_log_size=100 * 1024 * 1024,
                  backup_count=5):
    """
    Configures logging with rotation.
    """
    current_directory = get_script_directory()
    log_path = os.path.join(current_directory, log_dir)
    os.makedirs(log_path, exist_ok=True)


    log_file_path = os.path.join(log_path, log_file)
    handler = RotatingFileHandler(log_file_path, maxBytes=max_log_size, backupCount=backup_count, encoding='utf-8')
    # formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    formatter = logging.Formatter('%(message)s')
    handler.setFormatter(formatter)

    logging.basicConfig(level=logging.INFO, handlers=[handler])

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

def init_geoip_reader(directory_name="GeoLite2-City_20240517", db_file="GeoLite2-City.mmdb"):
    """
    Initializes the GeoIP reader.
    """
    current_directory = get_script_directory()
    db_path = os.path.join(current_directory, directory_name, db_file)
    logging.info(f"The GeoIP reader path: {db_path}")
    try:
        readerObj = Reader(db_path)
        return readerObj
    except Exception as e:
        logging.error(f"Error initializing GeoIP reader: {e}")
        return None


# def configure_mqtt_client(client, reader, on_connect, on_disconnect, on_publish, on_message, on_subscribe, on_unsubscribe, on_log):
#     """
#     Configures the MQTT client with the necessary callbacks and settings.
#     """
#     client.on_connect = on_connect
#     client.on_disconnect = on_disconnect
#     client.on_publish = on_publish
#     client.on_message = on_message
#     client.on_subscribe = on_subscribe
#     client.on_unsubscribe = on_unsubscribe
#     client.on_log = on_log
#     client.user_data_set(reader)





def on_connect(client, userdata, flags, rc):
    try:
        client_ip = client._sock.getpeername()[0] if client._sock else "Unknown"
        client_id = client._client_id.decode("utf-8") if client._client_id else "Unknown"
        reader = userdata

        # Check if location is None
        if reader is None:
            country_name = "Unknown"
        else:
            location = reader.city(client_ip)
            country_name = location.country.name

        username = client._username.decode("utf-8") if client._username else "Unknown"
        password = client._password.decode("utf-8") if client._password else "Unknown"

        with mutex:
            logging.info(f"Connection established with: result_code: {rc} | Client_ID: {client_id} | User: {username} | Password: {password} | Client_IP: {client_ip} | Country: {country_name}")
            if rc == 5:
                failed_connections[client_ip] += 1
                if failed_connections[client_ip] > BRUTE_FORCE_THRESHOLD:
                    logging.warning(f"Potential Brute_Force_Attack detected from: Client_IP: {client_ip} | Country: {country_name}")

            connections[client_ip] += 1
            message_counts[client_ip].append(time.time())
            if len(message_counts[client_ip]) > DOS_THRESHOLD:
                message_counts[client_ip].popleft()

            if len(message_counts[client_ip]) > 1:
                delta = message_counts[client_ip][-1] - message_counts[client_ip][0]
                if delta < 0.001:
                    logging.warning(f"Potential DoS_Attack detected from: Client_IP: {client_ip} | Country: {country_name}")
    except Exception as e:
        logging.error(f"[on_connect] Error on getting the country/city from DB: {e}")


def on_disconnect(client, userdata, rc):
    client_ip = client._sock.getpeername()[0] if client._sock else "Unknown"
    client_id = client._client_id.decode("utf-8") if client._client_id else "Unknown"
    logging.info(f"Disconnected with: result_code: {rc} | Client_ID: {client_id} | Client_IP: {client_ip}")


def on_publish(client, userdata, mid):
    try:
        client_ip = client._sock.getpeername()[0] if client._sock else "Unknown"
        client_id = client._client_id.decode("utf-8") if client._client_id else "Unknown"
        reader = userdata
        # Check if location is None
        if reader is None:
            country_name = "Unknown"
        else:
            location = reader.city(client_ip)
            country_name = location.country.name
        logging.info(f"Message published with: mid: {mid} | Client_ID: {client_id} | Client_IP: {client_ip} | Country: {country_name}")
    except Exception as e:
        logging.error(f"[on_publish] Error on getting the country/city from DB: {e}")


def on_message(client, userdata, msg):
    # Capture network information around message receive (optional)
    try:
        captured_packets = sniff(count=1, timeout=0.1, filter="tcp")  # Capture only TCP packets
    except OSError:
        captured_packets = None

    # Extract source IP and potential MQTT client ID from captured packets
    if msg is None:
        payload = "Unknown"
    else:
        payload = msg.payload.decode(errors='ignore')
    reader = userdata
    # Check if location is None
    # if reader is None:
    #     country_name = "Unknown"
    # else:
    #     location = reader.city(client_ip)
    #     country_name = location.country.name
    # Check if message is None
    source_ip = None
    mqtt_client_id = None
    if captured_packets:
        for packet in captured_packets:
            if (packet.haslayer(TCP) and packet.haslayer(IP)):
                source_ip = packet[IP].src
                # Check for potential MQTT traffic based on port and flags (heuristic)
                if packet[TCP].dport == 1883 and (packet[TCP].flags & 0x0F) == 0x02:  # Check for SYN flag
                    try:
                        # Attempt to decode MQTT payload assuming basic structure
                        mqtt_data = packet[TCP].payload.decode('utf-8')
                        # Extract potential client ID from the first part of the payload (heuristic)
                        mqtt_client_id = mqtt_data.split()[0]
                    except (UnicodeDecodeError, IndexError):
                        pass  # Handle potential decoding or parsing errors
    logging.info(f"Received message on: Topic: {msg.topic} | msg: {payload} | Client_ID: {mqtt_client_id} | Client_IP: {source_ip}") #| Country: {country_name}")

    # try:
    #     client_ip = client._sock.getpeername()[0] if client._sock else "Unknown"
    #     client_id = client._client_id.decode("utf-8") if client._client_id else "Unknown"
    #     reader = userdata
    #     # Check if location is None
    #     if reader is None:
    #         country_name = "Unknown"
    #     else:
    #         location = reader.city(client_ip)
    #         country_name = location.country.name
    #     # Check if message is None
    #     if msg is None:
    #         payload = "Unknown"
    #     else:
    #         payload = msg.payload.decode(errors='ignore')
    #
    #     logging.info(f"Received message on: Topic: {msg.topic} | msg: {payload} | Client_ID: {client_id} | Client_IP: {client_ip} | Country: {country_name}")
    #
    #     with mutex:
    #         if client._username == VALID_USERNAME and client._password == VALID_PASSWORD:
    #             logging.info(f"Authentication successful for: Client_IP: {client_ip} | Country: {location}")
    #         else:
    #             logging.warning(f"Authentication failed for: Client_IP: {client_ip} | Country: {country_name} | User: {client._username} | Password: {client._password}")
    #             failed_connections[client_ip] += 1
    #             login_attempts[client_ip].append((client._username, client._password))
    #             if failed_connections[client_ip] > BRUTE_FORCE_THRESHOLD:
    #                 logging.warning(f"asta printeaaza!!!!!!!!! Potential brute force attack detected from Client_IP: {client_ip} | number_of_tries: {failed_connections[client_ip]} | Country: {country_name} | Credentials: \n\tU: {[attempt[0] for attempts in login_attempts.values() for attempt in attempts]} \n\tP: {[attempt[1] for attempts in login_attempts.values() for attempt in attempts]}")
    #
    #         message_counts[client_ip].append(time.time())
    #         if len(message_counts[client_ip]) > DOS_THRESHOLD:
    #             message_counts[client_ip].popleft()
    #
    #         if len(message_counts[client_ip]) > 1:
    #             time_delta = message_counts[client_ip][-1] - message_counts[client_ip][0]
    #             if time_delta < 0.001:
    #                 logging.warning(f" asta printeaaza!!!!!!!!! Potential DoS attack detected from Client_IP: {client_ip} | Country: {country_name} | Number of messages in {time_delta} ms: {len(message_counts[client_ip])}")
    # except Exception as e:
    #     logging.error(f"[on_message] Error on getting the country/city from DB: {e}")


def on_subscribe(client, userdata, mid, granted_qos):
    try:
        client_ip = client._sock.getpeername()[0] if client._sock else "Unknown"
        client_id = client._client_id.decode("utf-8") if client._client_id else "Unknown"
        logging.info(f" intra  AICI!!!!!!!!!!!!!!!!!!!!!!!!")
        try:
            # Check if location is None
            if reader is None:
                country_name = "Unknown"
            else:
                location = reader.city(client_ip)
                country_name = location.country.name
        except Exception as e:
            country_name = "Unknown"
            logging.error(f"[on_subscribe] Error on getting the country/city from DB: {e}")

        if userdata is not None and '#' in userdata:
            root_topic = "#"
        else:
            root_topic = "Unknown"
        logging.info(f"Subscribed with: mid: {mid} | QoS {granted_qos} | Client_ID: {client_id} | Client_IP: {client_ip}| Topic: {root_topic} | Country: {country_name}")

        dummy_topics = {
            "home/temperature": lambda: f"{random.uniform(20.0, 25.0):.2f}",
            "home/humidity": lambda: f"{random.uniform(30.0, 50.0):.2f}",
            "home/door": lambda: random.choice(["open", "closed"]),
            "securitySensors/entrance": lambda: random.choice(["open", "closed"]),
            "securitySensors/mainRoom": lambda: random.choice(["motionDetected", "motionUndetected"]),
            "securitySensors/vault": lambda: random.choice(["open", "closed"]),
            "securitySensors/homeAlarm": lambda: random.choice(["on", "off"])
        }

        if userdata is not None and '#' in userdata:
            logging.warning(f"Potential Sniff_Attack detected from: Client_IP: {client_ip} | mid: {mid} | QoS {granted_qos} | Client_ID: {client_id} | Topic: {root_topic} | Country: {country_name}")
            for topic, fake_message in dummy_topics.items():
                client.publish(topic, fake_message)
            logging.warning(f"Sent_dummy_data to the possible Sniff Attacker: IP: {client_ip} | | Client_ID: {client_id} | Country: {country_name}")
    except Exception as e:
        logging.error(f"[on_subscribe] Error : {e}")


def on_unsubscribe(client, userdata, mid):
    try:
        client_ip = client._sock.getpeername()[0] if client._sock else "Unknown"
        client_id = client._client_id.decode("utf-8") if client._client_id else "Unknown"
        reader = userdata
        # Check if location is None
        if reader is None:
            country_name = "Unknown"
        else:
            location = reader.city(client_ip)
            country_name = location.country.name
        logging.info(f"Unsubscribed with: mid: {mid} | Client_ID: {client_id} | Client_IP: {client_ip}| Country: {country_name}")
    except Exception as e:
        logging.error(f"[on_unsubscribe] Error on getting the country/city from DB: {e}")


def on_log(client, userdata, level, buf):
    client_id = client._client_id.decode("utf-8") if client._client_id else "Unknown"
    logging.info(f"Log: {buf} | Client ID: {client_id}")


def parse_mqtt_connect_packet(payload):
    try:
        if len(payload) < 10:
            raise ValueError("Payload too short to be a valid MQTT Connect packet!")

        proto_name_len = struct.unpack("!H", payload[:2])[0]
        if len(payload) < 2 + proto_name_len + 4:
            raise ValueError("Payload too short to contain protocol name and version!")
        proto_name = payload[2:2 + proto_name_len].decode()
        version = payload[2 + proto_name_len]
        connect_flags = payload[3 + proto_name_len]
        keep_alive = struct.unpack("!H", payload[4 + proto_name_len:6 + proto_name_len])[0]

        index = 6 + proto_name_len
        if len(payload) < index + 2:
            raise ValueError("Payload too short to contain Client ID length!")
        client_id_len = struct.unpack("!H", payload[index:index + 2])[0]
        index += 2
        if len(payload) < index + client_id_len:
            raise ValueError("Payload too short to contain Client ID!")

        client_id = payload[index:index + client_id_len].decode()
        index += client_id_len

        username = None
        password = None
        if connect_flags & 0x80:
            if len(payload) < index + 2:
                raise ValueError("Payload too short to contain username length!")
            user_len = struct.unpack("!H", payload[index:index + 2])[0]
            index += 2
            if len(payload) < index + user_len:
                raise ValueError("Payload too short to contain username!")
            username = payload[index:index + user_len].decode()
            index += user_len
        if connect_flags & 0x40:
            if len(payload) < index + 2:
                raise ValueError("Payload too short to contain password length!")
            pass_len = struct.unpack("!H", payload[index:index + 2])[0]
            index += 2
            if len(payload) < index + pass_len:
                raise ValueError("Payload too short to contain password!")
            password = payload[index:index + pass_len].decode()

        return client_id, username, password
    except (struct.error, ValueError) as e:
        logging.error(f"Failed to parse MQTT Connect packet: {e}")
        return None, None, None


def pkt2dict(pkt) -> dict:
    packet_dict = {}
    sublayer = None

    for line in pkt.show2(dump=True).split('\n'):
        if '###' in line:
            if '|###' in line:
                sublayer = line.strip('|#[] ')
                if sublayer:
                    packet_dict[layer][sublayer] = {}
            else:
                layer = line.strip('#[] ')
                if layer:
                    packet_dict[layer] = {}
        elif '=' in line:
            key, val = line.split('=', 1)
            key = key.strip('| ').strip()
            val = val.strip('\' ')

            if '|' in line and sublayer:
                packet_dict[layer][sublayer][key] = val
            else:
                packet_dict[layer][key] = val
        else:
            logging.debug("pkt2dict packet not decoded: " + line)

    # Logic to extract the country from the packet
    try:
        if reader is None:
            country_name = "Unknown"
        else:
            # Assuming 'ip_src' is the source IP address field from the packet
            ip_src = pkt.getlayer('IP').src
            location = reader.city(ip_src)
            country_name = location.country.name
    except Exception as e:
        country_name = "Unknown"
        logging.error(f"[pkt2dict] Error on getting the country/city from DB: {e}")

    # Add the country to the dictionary
    packet_dict['Country'] = country_name

    return packet_dict


def packet_callback(packet):
    try:
        # Check if the packet has an MQTT layer
        if MQTT in packet:
            with mutex:
                output = pkt2dict(packet)
                ip_src = output['IP']["src"]

                if output['MQTT fixed header']["type"] == "CONNECT":
                    username = output["MQTT connect"]["username"]
                    password = output["MQTT connect"]["password"]

                    message_counts[ip_src].append(time.time())
                    if len(message_counts[ip_src]) > DOS_THRESHOLD:
                        message_counts[ip_src].popleft()

                    if len(message_counts[ip_src]) > 1:
                        time_delta = message_counts[ip_src][-1] - message_counts[ip_src][0]
                        if time_delta < 1:
                            if 'Possible_Attack' not in output:
                                output['Possible_Attack'] = {}
                            output['Possible_Attack']['attack'] = True
                            output['Possible_Attack']['Possible_DoS_Attack'] = True
                            output['Possible_Attack']['number_of_messages'] = len(message_counts[ip_src])
                            output['Possible_Attack']['time_delta(ms)'] = time_delta

                    if username != VALID_USERNAME or password != VALID_PASSWORD:
                        failed_connections[ip_src] += 1
                        login_attempts[ip_src].append((username, password))
                        last_trigger = time.time()
                        logging.warning(f"Authentication= Failed ==> IP_src= {ip_src} | number_of_tries= {failed_connections[ip_src]} | username= {username} | password= {password}")
                        if failed_connections[ip_src] > BRUTE_FORCE_THRESHOLD:
                            if 'Possible_Attack' not in output:
                                output['Possible_Attack'] = {}
                            output['Possible_Attack']['attack'] = True
                            output['Possible_Attack']['Possible_Brute_Force_Attack'] = True
                            output['Possible_Attack']['number_of_tries'] = failed_connections[ip_src]
                        else:
                            if time.time() - last_trigger > 100:
                                failed_connections[ip_src] = 0


                if output['MQTT fixed header']["type"] == "SUBSCRIBE":
                    topic = output["MQTT subscribe"]["MQTT topic"]["topic"]
                    if ip_src != "127.0.0.1" and ip_src != "::1":
                        if topic == "#" or topic.lower().startswith("sys/"):
                            dummy_topics = {
                                "home/temperature": lambda: f"{random.uniform(20.0, 25.0):.2f}",
                                "home/humidity": lambda: f"{random.uniform(30.0, 50.0):.2f}",
                                "home/door": lambda: random.choice(["open", "closed"]),
                                "securitySensors/entrance": lambda: random.choice(["open", "closed"]),
                                "securitySensors/mainRoom": lambda: random.choice(["motionDetected", "motionUndetected"]),
                                "securitySensors/vault": lambda: random.choice(["open", "closed"]),
                                "securitySensors/homeAlarm": lambda: random.choice(["on", "off"])
                            }

                            if ip_src not in subscriptions:
                                subscriptions[ip_src] = []
                            subscriptions[ip_src].append((topic, time.time()))
                            if 'Possible_Attack' not in output:
                                output['Possible_Attack'] = {}
                            output['Possible_Attack']['attack'] = True
                            output['Possible_Attack']['Possible_Sniff_Attack'] = True
                            for topic, fake_message in dummy_topics.items():
                                client.publish(topic, fake_message)

                # logging.info(f"Packet captured: {packet.show(dump=True)}")
                # logging.info(f"Packet captured: {" | ".join(packet.show(dump=True).split("\n"))}")
                # logging.info(f"MQTT Packet Captured from Country={country_name}: {re.sub(r'\s+', ' ', packet.show(dump=True))}")

                #logging.info(pkt2dict(packet))
                logging.info(json.dumps(output, separators=(',', ':')))



        # if IP in packet and TCP in packet:
        #     ip_src = packet[IP].src
        #     try:
        #         sport = packet[TCP].sport
        #         dport = packet[TCP].dport
        #         payload = bytes(packet[TCP].payload).decode(errors='ignore')
        #
        #         with mutex:
        #             # logging.info(f"Packet captured: {packet.show(dump=True)}")
        #             # logging.info(f"Packet captured: {" | ".join(packet.show(dump=True).split("\n"))}")
        #             logging.info(f"Packet captured: {re.sub(r'\s+', ' ', packet.show(dump=True))}")
        #
        #
        #         if (dport == 1883 or dport == 1884) and packet[TCP].payload:
        #             payload = bytes(packet[TCP].payload)
        #             if payload[0] >> 4 == 1:
        #                 client_id, username, password = parse_mqtt_connect_packet(payload[1:])
        #                 logging.info(f"MQTT Connect Packet: Client ID: {client_id} | Username: {username} | Password: {password}")
        #                 if username or password:
        #                     logging.warning(f"ALERT: Credentials visible in MQTT Connect packet from {ip_src}:{sport}. Username: {username}, Password: {password}")
        #     except Exception as e:
        #         logging.error(f"Error on processing packet: {e}")
    except Exception as e:
        logging.error(f"Packet callback error: {e}")


def start_packet_sniffer(interface=None):
    # logging.info("Started the packet sniffer")
    # sniff(filter="host localhost", prn=packet_callback, store=0)

    logging.info("Started the packet sniffer")
    try:
        # Check if running as administrator
        if not scapy.conf.L3socket:
            logging.error("Scapy requires administrative privileges to capture packets.")
            raise RuntimeError("Scapy requires administrative privileges to capture packets.")

        # List available interfaces
        # interfaces = scapy.get_if_list()
        # if not interface:
        #     interface = interfaces[0]  # Default to the first interface
        #     logging.info(f"No interface specified. Using default interface: {interface}")
        #
        # logging.info(f"Available interfaces: {interfaces}")
        # logging.info(f"Using interface: {interface}")

        # Start packet sniffer
        # scapy.sniff(iface=interface, filter="host localhost", prn=packet_callback, store=0)
        # List available network interfaces
        # logging.info("Available network interfaces:", get_if_list())

        iface_name = '\\Device\\NPF_Loopback'  # Replace with your network interface name
        scapy.sniff(iface=iface_name, filter="tcp port 1883", prn=packet_callback, store=0)  # --> local on my Desktop(W11)
        # scapy.sniff(filter="tcp port 1883", prn=packet_callback, store=0)
    except Exception as e:
        logging.error(f"Packet sniffer error: {e}")



# Global settings and state
DOS_THRESHOLD = 10
BRUTE_FORCE_THRESHOLD = 10
VALID_USERNAME = "validuser"
VALID_PASSWORD = "validpassword"

connections = defaultdict(int)
subscriptions = {}
failed_connections = defaultdict(int)
message_counts = defaultdict(deque)
login_attempts = defaultdict(list)
mutex = threading.Lock()



if __name__ == "__main__":
    setup_logging()
    reader = init_geoip_reader()

    client = mqtt.Client()
    """
    Configures the MQTT client with the necessary callbacks and settings.
    """
    host = "localhost"  # "185.237.15.251" #"localhost"#"test.mosquitto.org"
    port = 1883
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish
    client.on_message = on_message
    client.on_subscribe = on_subscribe
    client.on_unsubscribe = on_unsubscribe
    client.on_log = on_log
    # configure_mqtt_client(client, reader, on_connect, on_disconnect, on_publish, on_message, on_subscribe, on_unsubscribe, on_log)

    try:
        # client.username_pw_set("rw", password="readwrite")
        # client.connect("185.237.15.251", 1883, 60)

        try:
            client.username_pw_set(VALID_USERNAME, VALID_PASSWORD)
            client.connect(host, port, 60)
            logging.info(f"Successfully connected to MQTT broker at {host}:{port}")
        except Exception as e:
            logging.error(f"Failed to connect to MQTT broker at {host}:{port} - {e}")
            raise e

        threading.Thread(target=start_packet_sniffer, daemon=True).start()
        client.loop_start()
        client.subscribe("#")

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("MQTT Honeypot is shutting down")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        if client.is_connected():
            client.loop_stop()
            client.disconnect()
        reader.close()
        logging.info("Resources have been released")