# Network-Monitoring-and-Grafana
---

## **Nmap Scan Processing Script**

This Python script is designed to process Nmap scan results, store the data in a MySQL database, and send notifications via Discord and email. It can parse Nmap XML output, identify changes in the network, and log those changes into a database for further analysis.

### **Features:**
- **Parse Nmap XML Output:** Extracts version, command line, hosts, ports, and service details from Nmap XML reports.
- **Database Storage:** Stores scan results, hosts, and ports in a MySQL database.
- **Notifications:** Supports sending notifications of changes via Discord and email.
- **Change Detection:** Tracks new hosts, new ports, and state changes for existing ports.
- **Error Handling:** Rollbacks database changes if an error occurs during insertion.

### **Requirements:**
### **Prerequisites:**
Before running the scan and script, ensure you have the following:
1. **Nmap** installed on your system.
2. The Python environment is set up with the necessary dependencies (see previous sections for package installation).
3. A properly configured `.env` file with MySQL, Discord, and email credentials.

#### **Python Packages:**
1. `mysql-connector-python`
2. `requests`
3. `python-dotenv`
4. `smtplib`
5. `argparse`

You can install the dependencies using:
```bash
pip install mysql-connector-python requests python-dotenv
```

### **Environment Variables (`.env` File):**

The `.env` file should contain all necessary configuration variables like database credentials, webhook URLs, and email settings. Below is the structure of the `.env` file:

```ini
# MySQL Database Credentials
DB_HOST=localhost/ip
DB_USER=your user
DB_PASSWORD=your_password
DB_NAME=nmap_scans

# Discord Webhook for Notifications
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your_webhook_id

# Email Notifications Configuration
EMAIL_USERNAME=your_email@example.com
EMAIL_PASSWORD=your_email_password
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_RECIPIENT=recipient@example.com

# Path to Nmap XML file (optional)
NMAP_XML_PATH=/path/to/nmap_output.xml

# Enable or disable notifications
SEND_DISCORD_NOTIFICATIONS=true
SEND_EMAIL_NOTIFICATIONS=false
```
---

## **How to Run the Nmap Scan and Process the Results with the Script**
### **Command Overview:**

The provided command will run an Nmap scan on the local network (`192.168.0.0/24`), check for service versions (`-sV`), perform a fast scan (`-F`), and use two specific Nmap scripts:
- **`http-title`**: Extracts the HTTP title of the web servers.
- **`ssl-cert`**: Retrieves SSL certificate information.

The scan results will be saved in three formats: `.nmap`, `.xml`, and `.gnmap` with the `-oA` option (which outputs in all formats at once). After the scan, the Python script `nmap2mysql.py` will process the XML output and store it in the MySQL database.

### **Steps to Run the Command:**

1. **Run the Nmap Command**:
   - Open a terminal and execute the following command:
   
   ```bash
   nmap -sV -F --script=http-title,ssl-cert -oA nmap_output 192.168.0.0/24
   ```

   This command does the following:
   - Scans the `192.168.0.0/24` network.
   - Uses the `http-title` and `ssl-cert` scripts to gather extra information.
   - Outputs the result in multiple formats (`nmap_output.xml`, `nmap_output.nmap`, `nmap_output.gnmap`).

2. **Run the Python Script**:
   - After the scan completes, run the following command to process the XML output and insert the data into the MySQL database:

   ```bash
   python nmap2mysql.py --xml_file nmap_output.xml
   ```

   Alternatively, you can configure the `.env` file to automatically detect the XML output:
   - Set the `NMAP_XML_PATH` in your `.env` file to `nmap_output.xml`:
     ```ini
     NMAP_XML_PATH=nmap_output.xml
     ```
   - Then, simply run:
     ```bash
     python nmap2mysql.py
     ```

---

### **Detailed Breakdown:**

- **Nmap Command**:
   ```bash
   nmap -sV -F --script=http-title,ssl-cert -oA nmap_output 192.168.0.0/24
   ```
   - **`-sV`**: Detects service versions on open ports.
   - **`-F`**: Fast scan mode (scans fewer ports).
   - **`--script=http-title,ssl-cert`**: Runs two Nmap scripts (`http-title` and `ssl-cert`) to gather additional information.
   - **`-oA nmap_output`**: Saves the output in multiple formats with the base name `nmap_output` (produces `nmap_output.xml`, `nmap_output.nmap`, and `nmap_output.gnmap`).

- **Python Script**:
   ```bash
   python nmap2mysql.py --xml_file nmap_output.xml
   ```
   - This command runs the script and imports the Nmap XML scan data into the MySQL database.
   - If the path to the XML file is specified in the `.env` file, you can omit the `--xml_file` argument.

---

### **Example of Full Command Sequence**:

```bash
nmap -sV -F --script=http-title,ssl-cert -oA nmap_output 192.168.0.0/24 && python nmap2mysql.py --xml_file nmap_output.xml
```
---
### **How It Works:**

1. **Parsing Nmap XML (`parse_nmap_xml`)**:
   - Reads and parses the XML file produced by Nmap.
   - Extracts key information, including host IPs, service details, SSL certificates, HTTP titles, and port states (open, closed, or filtered).

2. **Database Setup (`create_database` and `create_tables`)**:
   - Connects to a MySQL server using credentials from the `.env` file.
   - Creates the necessary tables (`scans`, `hosts`, `ports`, `change_log`) if they don't already exist.

3. **Data Insertion (`insert_data`)**:
   - Inserts or updates scan, host, and port data into the MySQL database.
   - Uses SHA-256 hashes to uniquely identify hosts and ports.

4. **Change Detection (`log_change`)**:
   - Detects changes such as new hosts or port state changes.
   - Logs changes in the `change_log` table and triggers notifications.

5. **Notifications (`send_discord_notification` and `send_email`)**:
   - Sends change notifications to a Discord channel or an email recipient if enabled.
   - Discord messages are limited to 2000 characters to comply with Discord's API limits.

---
### **Tables Structure:**

1. **`scans` Table**:
   - Stores metadata of each Nmap scan, including version, command line used, start time, elapsed time, total hosts, and a unique scan hash.

2. **`hosts` Table**:
   - Stores details about each host detected during the scan, including IP address, hostname, OS, and number of ports tested.

3. **`ports` Table**:
   - Stores details about open, closed, or filtered ports, including the protocol, service information, and SSL certificates.

4. **`change_log` Table**:
   - Logs changes detected in the network, such as new hosts or changes in port state.
