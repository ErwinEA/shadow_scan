# Shadow Scan



**ShadowScan** is a low-level network forensic tool designed for Silent Asset Discovery and Infrastructure Auditing. Unlike traditional scanners that trigger security alerts through Transmission Control Protocol handshakes, ShadowScan operates at the Data Link Layer to map a network using Address Resolution Protocol interrogation and Organizationally Unique Identifier fingerprinting.

---

### Core Capabilities

* Silent Address Resolution Protocol Probing: Identifies active hosts by bypassing network firewalls that block Internet Control Message Protocol requests but must respond to Address Resolution Protocol.
* Organizationally Unique Identifier Forensic Fingerprinting: Cross-references Media Access Control addresses against the *IEEE to identify physical hardware manufacturers.
* Tactical Watchlist: Inputs unknown MAC address to **watchlist.json**. Records time of first siting, as a forensic ledger.
* Media Access Control Aging and State Tracking: Distinguishes between active, stale, and randomized hardware addresses to eliminate ghost devices.

---

### Command Interface and Usage

The tool operates through a **Terminal User Interface** and does not require a web browser.

#### 1. Execution

To start the application, navigate to the project directory and run the main Python file:

```bash
python main.py

```

#### 2. User Inputs

When prompted by the command line interface, enter the following parameters:

* **Target Range:** Enter the network range in Classless Inter-Domain Routing notation, such as 192.168.1.1/24.
* **Interface:** Enter the physical Network Interface Card to use for sniffing, such as eth0 or wlan0.
* **Scan Intensity:** Enter a whole number from 1 to 5 to determine the delay between packets. Lower numbers are more stealthy.

#### 3. Keyboard Shortcuts

* **ctrl + e:** Stops the current scan session to allow you to enter and check a new Internet Protocol range.
* **ctrl + c or Empty Line:** Terminates the entire script and closes the application.

---

### Project Structure

* **main.py:** The primary engine that handles packet crafting and the terminal display.
* **reference.json:** The processed data mapping hardware prefixes to specific vendors, these are scrapped from the IEEE OUI database.
* **watchlist.json:** A list containing your unauthorized hardware addresses that showed up during the scan.


**Forensic Note:** ShadowScan is intended for authorized security auditing and network management only. Unauthorized scanning of networks you do not own may be a violation of local laws.
