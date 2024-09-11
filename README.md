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

### **Usage:**

1. **Command-Line Arguments**:
   - You can provide the Nmap XML file path via command-line arguments or through the `.env` file.
   ```bash
   python script.py --xml_file /path/to/nmap_output.xml
   ```

2. **Sample `.env` File**:
   ```ini
   DB_HOST=localhost
   DB_USER=nmap_user
   DB_PASSWORD=nthuli
   DB_NAME=nmap_scans
   DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your_webhook_id
   EMAIL_USERNAME=your_email@example.com
   EMAIL_PASSWORD=your_email_password
   EMAIL_HOST=smtp.example.com
   EMAIL_PORT=587
   EMAIL_RECIPIENT=recipient@example.com
   SEND_DISCORD_NOTIFICATIONS=true
   SEND_EMAIL_NOTIFICATIONS=false
   ```

3. **Database Setup**:
   - The script will automatically create the necessary database and tables based on the information in the `.env` file.

4. **Notification Configurations**:
   - To enable or disable Discord or email notifications, set `SEND_DISCORD_NOTIFICATIONS` and `SEND_EMAIL_NOTIFICATIONS` in the `.env` file as `true` or `false`.

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

---

### **Troubleshooting:**

- **Discord Webhook Failure**: Check if `DISCORD_WEBHOOK_URL` is correct and reachable. Log the response from Discord to debug.
- **Email Sending Errors**: Ensure that your email host, port, username, and password are correctly configured in the `.env` file.
- **Database Errors**: Ensure that the MySQL service is running and that the credentials in the `.env` file are correct. You can also try manually connecting to the database using the same credentials to debug.
