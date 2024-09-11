import hashlib
import os
import xml.etree.ElementTree as ET
import mysql.connector
from datetime import datetime
import argparse
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import requests
from time import time

# Load environment variables from .env file
load_dotenv()
current_timestamp = int(time() * 1000)  # Get current UNIX timestamp in milliseconds

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    nmap_version = root.get('version', '')
    command_line = root.get('args', '')

    scan_start_time = root.get('start')
    if scan_start_time is not None:
        # timestamps set to match native grafana format
        scan_start_timestamp = int(scan_start_time) * 1000

    elapsed_time = ''
    elapsed_time_elem = root.find('runstats/finished')
    if elapsed_time_elem is not None:
        elapsed_time = elapsed_time_elem.get('elapsed')

    total_hosts = 0
    total_open_ports = 0

    hosts = []
    for host in root.findall('host'):
        total_hosts += 1
        ip = host.find('address').get('addr', '')

        hostname_elems = host.findall('hostnames/hostname')
        hostname = hostname_elems[0].get('name', '') if hostname_elems else ''

        os = 'Unknown'
        os_element = host.find('os')
        if os_element:
            os_match = os_element.find('osmatch')
            os = os_match.get('name', 'Unknown') if os_match else 'Unknown'

        ports_tested = 0
        ports_open = 0
        ports_closed = 0
        ports_filtered = 0

        ports = []
        ports_element = host.find('ports')
        if ports_element is not None:
            for port in ports_element.findall('port'):
                port_id = port.get('portid')
                protocol = port.get('protocol')
                state = port.find('state').get('state')
                if state == 'open':
                    ports_open += 1
                    total_open_ports += 1
                elif state == 'closed':
                    ports_closed += 1
                elif state == 'filtered':
                    ports_filtered += 1

                service = port.find('service')
                service_name = service.get('name', None) if service is not None else None
                service_product = service.get('product', None) if service is not None else None
                service_version = service.get('version', None) if service is not None else None
                service_ostype = service.get('ostype', None) if service is not None else None
                service_info = (service_product if service_product else '') + (' ' + service_version if service_version else '')
                http_title = None
                ssl_common_name = None
                ssl_issuer = None

                scripts = port.findall('script')
                for script in scripts:
                    if script.get('id') == 'http-title':
                        http_title = script.get('output')
                    elif script.get('id') == 'ssl-cert':
                        for table in script.findall('table'):
                            if table.get('key') == 'subject':
                                cn_elem = table.find("elem[@key='commonName']")
                                if cn_elem is not None:
                                    ssl_common_name = cn_elem.text
                            elif table.get('key') == 'issuer':
                                issuer_elems = {elem.get('key'): elem.text for elem in table.findall('elem')}
                                if 'commonName' in issuer_elems:
                                    ssl_issuer = f"{issuer_elems.get('commonName')} {issuer_elems.get('organizationName', '')}".strip()

                if service_ostype and os == 'Unknown':
                    os = service_ostype

                ports.append({
                    'port': port_id,
                    'protocol': protocol,
                    'state': state,
                    'service_name': service_name,
                    'service_info': service_info,
                    'http_title': http_title,
                    'ssl_common_name': ssl_common_name,
                    'ssl_issuer': ssl_issuer
                })

            extraports = ports_element.find('extraports')
            if len(extraports):
                extraports_count = int(extraports.get('count', '0'))
                extraports_state = extraports.get('state', '')
                if extraports_state == 'closed':
                    ports_closed += extraports_count
                elif extraports_state == 'filtered':
                    ports_filtered += extraports_count
                ports_tested += extraports_count

        host_start_time = host.get('starttime')
        host_end_time = host.get('endtime')
        start_timestamp = int(host_start_time) * 1000 if host_start_time else None
        end_timestamp = int(host_end_time) * 1000 if host_end_time else None

        hosts.append({
            'ip': ip,
            'hostname': hostname,
            'os': os,
            'ports_tested': ports_tested,
            'ports_open': ports_open,
            'ports_closed': ports_closed,
            'ports_filtered': ports_filtered,
            'start_time': start_timestamp,
            'end_time': end_timestamp,
            'ports': ports
        })

    scan = {
        'nmap_version': nmap_version,
        'command_line': command_line,
        'start_time': scan_start_time,
        'elapsed_time': elapsed_time,
        'total_hosts': total_hosts,
        'total_open_ports': total_open_ports
    }

    return scan, hosts

def create_database(db_name):
    # Initial connection without specifying the database
    conn = mysql.connector.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        charset='utf8mb4',
        collation='utf8mb4_unicode_ci'
    )
    c = conn.cursor()
    c.execute(f"CREATE DATABASE IF NOT EXISTS {db_name} DEFAULT CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_ci';")
    c.close()
    conn.close()

    # Reconnect with the specific database
    conn = mysql.connector.connect(
        host="localhost",
        user="nmap_user",
        password="nthuli",
        database=db_name,
        charset='utf8mb4',
        collation='utf8mb4_unicode_ci'
    )
    c = conn.cursor()

    # Create tables
    create_tables(c)

    conn.commit()
    return conn

def create_tables(c):
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nmap_version TEXT,
            command_line TEXT,
            start_time BIGINT,
            elapsed_time TEXT,
            total_hosts INT,
            total_open_ports INT,
            scan_hash VARCHAR(64)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS hosts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            scan_id INT,
            ip VARCHAR(255),
            hostname VARCHAR(255),
            os TEXT,
            ports_tested INT,
            ports_open INT,
            ports_closed INT,
            ports_filtered INT,
            first_seen BIGINT,
            last_seen BIGINT,
            unique_id VARCHAR(255),
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS ports (
            id INT AUTO_INCREMENT PRIMARY KEY,
            scan_id INT,
            host_id INT,
            port VARCHAR(20),
            protocol VARCHAR(10),
            state VARCHAR(20),
            service_name VARCHAR(255),
            service_info TEXT,
            http_title TEXT,
            ssl_common_name TEXT,
            ssl_issuer TEXT,
            open_date BIGINT,
            close_date BIGINT,
            UNIQUE INDEX idx_port_unique (host_id, port, protocol),
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
            FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ''')

    c.execute('''
        CREATE TABLE IF NOT EXISTS change_log (
            id INT AUTO_INCREMENT PRIMARY KEY,
            scan_id INT,
            description TEXT,
            change_type ENUM('new_host', 'port_state_change', 'new_port', 'scan_update', 'host_update'),
            details TEXT,
            detected_time BIGINT,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    ''')

def generate_unique_id(ip, hostname):
    return hashlib.sha256(f"{ip}_{hostname}".encode()).hexdigest()

def send_discord_notification(message):
    webhook_url = os.getenv('DISCORD_WEBHOOK_URL')
    if not webhook_url:
        print("Error: Discord Webhook URL not set in environment variables.")
        return

    headers = {'Content-Type': 'application/json'}
    data = {"content": message}

    if len(message) > 2000:
        print(f"Error: Message exceeds Discord's 2000 character limit. Length: {len(message)}")
        return

    response = requests.post(webhook_url, json=data, headers=headers)
    if response.status_code != 204:
        print(f"Discord webhook failed: Status code {response.status_code}, Response: {response.text}")
    else:
        print("Discord notification sent successfully.")

def send_email(subject, body):
    sender = os.getenv('EMAIL_USERNAME')
    recipient = os.getenv('EMAIL_RECIPIENT')
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient

    with smtplib.SMTP(os.getenv('EMAIL_HOST'), int(os.getenv('EMAIL_PORT'))) as server:
        server.starttls()
        server.login(sender, os.getenv('EMAIL_PASSWORD'))
        server.sendmail(sender, [recipient], msg.as_string())

def log_change(conn, scan_id, change_type, description):
    if change_type not in ['new_host', 'port_state_change', 'new_port', 'scan_update']:
        raise ValueError(f"Invalid change_type: {change_type}")

    c = conn.cursor()
    message = f"Scan ID: {scan_id}, Change Type: {change_type}, Description: {description}"
    try:
        c.execute("""
            INSERT INTO change_log (scan_id, description, change_type, detected_time)
            VALUES (%s, %s, %s, UNIX_TIMESTAMP())
            """, (scan_id, description, change_type))
        conn.commit()
        print("Logging change:", scan_id, change_type, description)
        
        if os.getenv('SEND_DISCORD_NOTIFICATIONS', 'false').lower() == 'true':
            send_discord_notification(message)

        if os.getenv('SEND_EMAIL_NOTIFICATIONS', 'false').lower() == 'true':
            send_email("Network Change Detected", message)
            
    except mysql.connector.Error as err:
        print("Failed inserting log change:", err)
        conn.rollback()  # Rollback to avoid partial changes
    finally:
        c.close()


def insert_or_update_host(conn, scan_id, host):
    c = conn.cursor()
    unique_id = generate_unique_id(host['ip'], host['hostname'])
    c.execute("SELECT id, first_seen, last_seen FROM hosts WHERE unique_id = %s", (unique_id,))
    existing_host = c.fetchone()

    if existing_host:
        host_id, first_seen, last_seen = existing_host
        if host['end_time'] > last_seen:
            c.execute("UPDATE hosts SET last_seen = %s WHERE id = %s", (host['end_time'], host_id))
            log_change(conn, scan_id, 'scan_update', f"Host {host['ip']} updated.")
    else:
        c.execute("""
            INSERT INTO hosts (scan_id, ip, hostname, os, ports_tested, ports_open, ports_closed, ports_filtered, first_seen, last_seen, unique_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (scan_id, host['ip'], host['hostname'], host['os'], host['ports_tested'], host['ports_open'], host['ports_closed'], host['ports_filtered'], host['start_time'], host['end_time'], unique_id))
        host_id = c.lastrowid
        log_change(conn, scan_id, 'new_host', f"New host {host['ip']} detected.")

    return host_id

def update_or_insert_port(conn, host_id, port, scan_id, current_timestamp):
    c = conn.cursor()
    # Check for existing port for the given host
    c.execute("""
        SELECT id, open_date, close_date FROM ports WHERE host_id = %s AND port = %s AND protocol = %s
        """, (host_id, port['port'], port['protocol']))
    existing_port = c.fetchone()

    if existing_port:
        port_id, open_date, close_date = existing_port
        # If port was previously closed and is now open, update open_date; if it's now closed, update close_date
        if port['state'] == 'open' and (close_date is not None or open_date is None):
            c.execute("""
                UPDATE ports SET state = %s, service_name = %s, service_info = %s, http_title = %s, ssl_common_name = %s, ssl_issuer = %s, open_date = %s, close_date = NULL WHERE id = %s
                """, (port['state'], port['service_name'], port['service_info'], port['http_title'], port['ssl_common_name'], port['ssl_issuer'], current_timestamp, port_id))
        elif port['state'] != 'open' and close_date is None:
            c.execute("""
                UPDATE ports SET close_date = %s WHERE id = %s
                """, (current_timestamp, port_id))
    else:
        # Insert new port if it does not exist
        c.execute("""
            INSERT INTO ports (scan_id, host_id, port, protocol, state, service_name, service_info, http_title, ssl_common_name, ssl_issuer, open_date)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (scan_id, host_id, port['port'], port['protocol'], port['state'], port['service_name'], port['service_info'], port['http_title'], port['ssl_common_name'], port['ssl_issuer'], current_timestamp if port['state'] == 'open' else None))
    conn.commit()

def insert_data(conn, scan, hosts, current_timestamp):
    c = conn.cursor()
    # Generate a unique hash for the scan to prevent duplicate scans
    scan_hash = hashlib.sha256(f"{scan['command_line']}_{scan['start_time']}".encode()).hexdigest()
    c.execute("SELECT id FROM scans WHERE scan_hash = %s", (scan_hash,))
    result = c.fetchone()

    if result:
        scan_id = result[0]
        print("Scan already exists. Updating existing records.")
    else:
        c.execute("""
            INSERT INTO scans (nmap_version, command_line, start_time, elapsed_time, total_hosts, total_open_ports, scan_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (scan['nmap_version'], scan['command_line'], scan['start_time'], scan['elapsed_time'], scan['total_hosts'], scan['total_open_ports'], scan_hash))
        scan_id = c.lastrowid

    for host in hosts:
        host_id = insert_or_update_host(conn, scan_id, host)
        for port in host['ports']:
            update_or_insert_port(conn, host_id, port, scan_id, current_timestamp)

    conn.commit()


def main():
    parser = argparse.ArgumentParser(description="Process Nmap scan results.")
    parser.add_argument("--xml_file", help="Path to the Nmap output XML file", default=os.getenv('NMAP_XML_PATH'))
    args = parser.parse_args()

    xml_file = args.xml_file

    # Ensure the XML file path is available
    if not xml_file:
        print("Error: XML file path must be provided either via the command-line argument or in the .env file.")
        return

    db_name = os.getenv('DB_NAME')

    # Create database and tables
    conn = create_database(db_name)

    # Parse XML and insert data into MySQL
    scan, hosts = parse_nmap_xml(xml_file)
    insert_data(conn, scan, hosts, current_timestamp)

    conn.close()


if __name__ == '__main__':
    main()
