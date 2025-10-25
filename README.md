# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/pedro33parreira/Threat-Hunting-Scenario-TOR/blob/main/threat-hunting-scenario-tor-event-creation)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "test-defender"
| where InitiatingProcessAccountName == "lokiid"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-10-24T08:21:43.0753332Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1451" height="574" alt="image" src="https://github.com/user-attachments/assets/fea60cfc-1394-4a22-acc2-789eff8e49fb" />



---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "test-defender"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.8.exe"
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1459" height="327" alt="image" src="https://github.com/user-attachments/assets/b91e145b-b872-4513-ae2a-62ebdaff6966" />



---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "test-defender"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1426" height="796" alt="image" src="https://github.com/user-attachments/assets/7ad22a0d-36cf-4014-a914-8fb05ef0890f" />



---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "test-defender"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc


```
<img width="1441" height="802" alt="image" src="https://github.com/user-attachments/assets/a8b1abbf-046f-4ce0-8f7e-b03a305a823b" />


---

Chronological Events\
08:21:43 AM (UTC) – File Discovery / Download Begins
Table Queried: DeviceFileEvents
Analyst located multiple file events containing “tor”.


File identified: tor-browser-windows-x86_64-portable-14.5.8.exe in
 C:\Users\Lokiid\Downloads\.


Additional TOR-related files were copied to the user’s desktop, including tor-shopping-list.txt, suggesting user interaction after download.


SHA256: 42175e455f814e5a691195c92df92695f68bca451af53ae405d7a5129898ad89


User: lokiid


Interpretation: Initial download and file manipulation of the TOR installer and related text artifacts, indicating possible intent to use or document TOR-based browsing.

10:21:43 AM – File Download / Rename
A file named tor-browser-windows-x86_64-portable-14.5.8.exe was detected in
 C:\Users\Lokiid\Downloads\.


Action: FileRenamed (likely from browser temporary file to final filename).


User: Lokiid


SHA256: 42175e455f814e5a691195c92df92695f68bca451af53ae405d7a5129898ad89


Interpretation: The user “Lokiid” downloaded the Tor Browser installer, beginning the unauthorized installation process.



10:27:10 AM – Process Execution (Silent Install Initiated)
A process creation event shows Tor Browser installer execution by the user “Lokiid”.


File executed: tor-browser-windows-x86_64-portable-14.5.8.exe


Path: C:\Users\Lokiid\Downloads\


Command line: "tor-browser-windows-x86_64-portable-14.5.8.exe" /S


Action type: ProcessCreated


Interpretation: The /S switch indicates a silent installation, likely without user prompts.



10:27:55 AM – Process Creation (Installation Continues)
A second process event confirms that the installer continued running.


Same executable and hash as before.


Interpretation: Indicates unpacking and deploying Tor Browser components to a destination folder.



10:28:14–10:28:26 AM – File Creation Events (Installation Output)
Multiple new files were created under
 C:\Users\Lokiid\Desktop\Tor Browser\Browser\TorBrowser\Tor\, including:
tor.txt


Torbutton.txt


Tor-Launcher.txt


tor.exe


A desktop shortcut Tor Browser.lnk


Interpretation: These artifacts confirm that the installation completed successfully and that Tor Browser was deployed to the “Lokiid” user’s desktop.

10:28:29 AM – Tor Browser Launched
Process created: firefox.exe


Location: C:\Users\Lokiid\Desktop\Tor Browser\Browser\firefox.exe


Action: ProcessCreated


Interpretation: This is the actual launch of the Tor Browser GUI, which uses a modified Firefox binary.



10:28:46 AM – Outgoing Network Connection Established
(Event described in your threat hunt narrative — data confirmed from network query)
Process: tor.exe
Path: C:\Users\Lokiid\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe


Remote IP: 80.239.189.84


Remote Port: 9001 (a known Tor relay port)


Action type: ConnectionSuccess (inferred)


Interpretation: The Tor service successfully connected to a known Tor node, confirming active use of the Tor network by the user “Lokiid”.


Additional connections were made over port 443, consistent with encrypted HTTPS traffic through Tor relays.


---

## Summary

This sequence clearly demonstrates unauthorized installation and use of the Tor Browser by the user “Lokiid” on the system “test-defender.” The activity bypassed normal network visibility and introduced encrypted outbound traffic to external Tor nodes.

Recommended Actions:
Immediately notify management of confirmed TOR activity.


Isolate or monitor the affected workstation for continued TOR processes.


Review proxy/firewall rules to block known TOR ports and relay IPs.


Conduct a user awareness and disciplinary review as per policy.

---

## Response Taken

TOR usage was confirmed on endpoint “test-defender” by the user “Lokiid”. The device was isolated and the user's direct manager was notified.

---
