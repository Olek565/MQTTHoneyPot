import paho.mqtt.client as mqtt
import logging
import logging_loki
from logging.handlers import RotatingFileHandler
import os
from datetime import datetime, timedelta
from scapy.all import sniff, IP, TCP, Ether, Raw
from collections import defaultdict, deque
import struct
import random
import threading
from geoip2.database import Reader
import time
import requests


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
                  max_log_size=10 * 1024 * 1024,
                  backup_count=5):
    """
    Configures logging with rotation.
    """
    current_directory = get_script_directory()
    log_path = os.path.join(current_directory, log_dir)
    os.makedirs(log_path, exist_ok=True)

    log_file_path = os.path.join(log_path, log_file)
    handler = RotatingFileHandler(log_file_path, maxBytes=max_log_size, backupCount=backup_count, encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    logging.basicConfig(level=logging.INFO, handlers=[handler])

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

    # Loki handler
    loki_handler = logging_loki.LokiHandler(
        url="http://loki:3100/loki/api/v1/push",
        tags={"application": "mqtt_honeypot"},
        version="1"
    )
    logging.getLogger('').addHandler(loki_handler)


def init_geoip_reader(directory_name="GeoLite2-City_20240517", db_file="GeoLite2-City.mmdb"):
    """
    Initializes the GeoIP reader.
    """
    current_directory = get_script_directory()
    db_path = os.path.join(current_directory, directory_name, db_file)
    return Reader(db_path)


def configure_mqtt_client(client, reader, on_connect, on_disconnect, on_publish, on_message, on_subscribe, on_unsubscribe, on_log):
    """
    Configures the MQTT client with the necessary callbacks and settings.
    """
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_publish = on_publish
    client.on_message = on_message
    client.on_subscribe = on_subscribe
    client.on_unsubscribe = on_unsubscribe
    client.on_log = on_log
    client.user_data_set(reader)


# Global settings and state
DOS_THRESHOLD = 100
BRUTE_FORCE_THRESHOLD = 10
VALID_USERNAME = "validuser"
VALID_PASSWORD = "validpassword"

connections = defaultdict(int)
failed_connections = defaultdict(int)
message_counts = defaultdict(deque)
login_attempts = defaultdict(list)
mutex = threading.Lock()


def on_connect(client, userdata, flags, rc):
    try:
        client_ip = client._sock.getpeername()[0] if client._sock else "Unknown"
        client_id = client._client_id.decode("utf-8") if client._client_id else "Unknown"
        reader = userdata
        location = reader.city(client_ip)
        country_name = location.country.name
        city_name = location.city.name
        username = client._username.decode("utf-8")
        password = client._password.decode("utf-8")

        with mutex:
            logging.info(f"Connection established with result code {rc} | Client ID: {client_id} | u: {username}, p: {password} | IP: {client_ip} | Country: {country_name}, City: {city_name}")
            if rc == 5:
                failed_connections[client_ip] += 1
                if failed_connections[client_ip] > BRUTE_FORCE_THRESHOLD:
                    logging.warning(f"Potential brute force attack detected from IP: {client_ip} (Country: {country_name}, City: {city_name})")

            connections[client_ip] += 1
            message_counts[client_ip].append(time.time())
            if len(message_counts[client_ip]) > DOS_THRESHOLD:
                message_counts[client_ip].popleft()

            if len(message_counts[client_ip]) > 1:
                delta = message_counts[client_ip][-1] - message_counts[client_ip][0]
                if delta < 0.001:
                    logging.warning(f"Potential DoS attack detected from IP: {client_ip} (Country: {country_name}, City: {city_name})")
    except Exception as e:
        logging.error(f"Error on getting the country/city from DB: {e}")


def on_disconnect(client, userdata, rc):
    client_ip = client._sock.getpeername()[0] if client._sock else "Unknown"
    client_id = client._client_id.decode("utf-8") if client._client_id else "Unknown"
    logging.info(f"Disconnected with result code {rc} | Client ID: {client_id} | IP: {client_ip}")


def on_publish(client, userdata, mid):
    try:
        client_ip = client._sock.getpeername()[0] if client._sock else "Unknown"
        client_id = client._client_id.decode("utf-8") if client._client_id else "Unknown"
        reader = userdata
        location = reader.city(client_ip)
        country_name = location.country.name
        city_name = location.city.name
        logging.info(f"Message published with mid {mid} | Client ID: {client_id} | IP: {client_ip} | Country: {country_name} | City: {city_name}")
    except Exception as e:
        logging.error(f"Error on getting the country/city from DB: {e}")


def on_message(client, userdata, msg):
    try:
        client_ip = client._sock.getpeername()[0] if client._sock else "Unknown"
        client_id = client._client_id.decode("utf-8") if client._client_id else "Unknown"
        reader = userdata
        location = reader.city(client_ip)
        country_name = location.country.name
        city_name = location.city.name
        payload = msg.payload.decode(errors='ignore')

        logging.info(f"Received message on Topic: {msg.topic}: {payload} | Client ID: {client_id} | IP: {client_ip} | Loc: {country_name}, {city_name}")

        with mutex:
            if client._username == VALID_USERNAME and client._password == VALID_PASSWORD:
                logging.info(f"Authentication successful for client {client_ip} (Country: {location}, City: {city_name})")
            else:
                logging.warning(f"Authentication failed for client {client_ip} (Country: {country_name}, City: {city_name}) with username: {client._username} and password: {client._password}")
                failed_connections[client_ip] += 1
                login_attempts[client_ip].append((client._username, client._password))
                if failed_connections[client_ip] > BRUTE_FORCE_THRESHOLD:
                    logging.warning(f"Potential brute force attack detected from IP (number of tries: {failed_connections[client_ip]}): {client_ip} (Country: {country_name}, City: {city_name}) | Credentials used: \n\tU: {[attempt[0] for attempts in login_attempts.values() for attempt in attempts]} \n\tP: {[attempt[1] for attempts in login_attempts.values() for attempt in attempts]}")

            message_counts[client_ip].append(time.time())
            if len(message_counts[client_ip]) > DOS_THRESHOLD:
                message_counts[client_ip].popleft()

            if len(message_counts[client_ip]) > 1:
                time_delta = message_counts[client_ip][-1] - message_counts[client_ip][0]
                if time_delta < 0.001:
                    logging.warning(f"Potential DoS attack detected from IP: {client_ip} (Country: {country_name}, City: {city_name}) | Number of messages in {time_delta} ms: {len(message_counts[client_ip])}")
    except Exception as e:
        logging.error(f"Error on getting the country/city from DB: {e}")


def on_subscribe(client, userdata, mid, granted_qos):
    try:
        client_ip = client._sock.getpeername()[0] if client._sock else "Unknown"
        client_id = client._client_id.decode("utf-8") if client._client_id else "Unknown"
        reader = userdata
        location = reader.city(client_ip)
        country_name = location.country.name
        city_name = location.city.name

        if userdata is not None and '#' in userdata:
            root_topic = "#"
        else:
            root_topic = "Unknown"
        logging.info(f"Subscribed with mid {mid} and QoS {granted_qos} | Client ID: {client_id} | IP: {client_ip}| Topic: {root_topic} | Country: {country_name} | City: {city_name}")

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
            logging.warning(f"Possible Sniff Attack with: IP: {client_ip}, mid {mid} and QoS {granted_qos} | Client ID: {client_id} | Topic: {root_topic}| Country: {country_name} | City: {city_name}")
            for topic, fake_message in dummy_topics.items():
                client.publish(topic, fake_message)
            logging.warning(f"Sent dummy data to the possible Sniff Attacker: IP: {client_ip} | | Client ID: {client_id}| Country: {country_name} | City: {city_name}")
    except Exception as e:
        logging.error(f"Error on getting the country/city from DB: {e}")


def on_unsubscribe(client, userdata, mid):
    try:
        client_ip = client._sock.getpeername()[0] if client._sock else "Unknown"
        client_id = client._client_id.decode("utf-8") if client._client_id else "Unknown"
        reader = userdata
        location = reader.city(client_ip)
        country_name = location.country.name
        city_name = location.city.name
        logging.info(f"Unsubscribed with mid {mid} | Client ID: {client_id} | IP: {client_ip}| Country: {country_name} | City: {city_name}")
    except Exception as e:
        logging.error(f"Error on getting the country/city from DB: {e}")


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


def packet_callback(packet):
    try:
        layers = []
        if Ether in packet:
            layers.append(packet[Ether].summary())
        if IP in packet:
            layers.append(packet[IP].summary())
        if TCP in packet:
            layers.append(packet[TCP].summary())
        if Raw in packet:
            layers.append(packet[Raw].summary())

        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            try:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                payload = bytes(packet[TCP].payload).decode(errors='ignore')

                with mutex:
                    logging.info(f"Packet captured: {packet.show(dump=True)}")

                if (dport == 1883 or dport == 1884) and packet[TCP].payload:
                    payload = bytes(packet[TCP].payload)
                    if payload[0] >> 4 == 1:
                        client_id, username, password = parse_mqtt_connect_packet(payload[1:])
                        logging.info(f"MQTT Connect Packet: Client ID: {client_id} | Username: {username} | Password: {password}")
                        if username or password:
                            logging.warning(f"ALERT: Credentials visible in MQTT Connect packet from {ip_src}:{sport}. Username: {username}, Password: {password}")
            except Exception as e:
                logging.error(f"Error on processing packet: {e}")
    except Exception as e:
        logging.error(f"Packet callback error: {e}")


def start_packet_sniffer(interface=None):
    logging.info("Started the packet sniffer")
    sniff(filter="host test.mosquitto.org", prn=packet_callback, store=0)

    logging.info("Started the packet sniffer")
    try:
        # Check if running as administrator
        if not scapy.conf.L3socket:
            raise RuntimeError("Scapy requires administrative privileges to capture packets.")

        # List available interfaces
        interfaces = scapy.get_if_list()
        if not interface:
            interface = interfaces[0]  # Default to the first interface
            logging.info(f"No interface specified. Using default interface: {interface}")

        logging.info(f"Available interfaces: {interfaces}")
        logging.info(f"Using interface: {interface}")

        # Start packet sniffer
        scapy.sniff(iface=interface, filter="host localhost", prn=packet_callback, store=0)
    except Exception as e:
        logging.error(f"Packet sniffer error: {e}")


if __name__ == "__main__":
    setup_logging()
    reader = init_geoip_reader()

    client = mqtt.Client()
    configure_mqtt_client(client, reader, on_connect, on_disconnect, on_publish, on_message, on_subscribe, on_unsubscribe, on_log)

    try:
        client.username_pw_set("rw", password="readwrite")
        client.connect("mqtt_broker", 1883, 60)

        threading.Thread(target=start_packet_sniffer, daemon=True).start()
        client.loop_start()
        client.subscribe("#")

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("MQTT Honeypot is shutting down")
    finally:
        client.loop_stop()
        client.disconnect()
        reader.close()
