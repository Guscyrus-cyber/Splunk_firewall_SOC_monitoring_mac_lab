 Splunk SOC Monitoring firewall Lab\
\
The goal of this lab was to ingest firewall-related data collected from a MacBook Pro into Splunk Enterprise and perform SOC monitoring activities to identify listening services, exposed ports, and potential attack surfaces through dashboards, reports, alerts, detections, and threat-hunting queries.\
\
Firewall Index (index=firewall)
=============================================================================================================================================================================================================================================================================================================

Firewall-related data shows:

exposed services,\
listening ports,\
applications accepting connections.

dataset: listening_ports.log\
came from bash: lsof -i -P -n which was saved and included to dataset\
index=firewall\
\
Search bar: index=firewall or index=firewall \| stats count by process

SOC analysts use firewall data to:

dentify open ports,\
identify exposed services,\
investigate unauthorized applications,\
review attack surface,\
detect suspicious listeners.

Step 1 — Create Firewall Index\
Status: Already completed in previous lab\
The firewall index had already been created during the Splunk lab setup previous lab and was reused for the Firewall SOC Monitoring Lab. The listening_ports.log dataset was uploaded into the existing index for analysis.\
\
Step 2 — Upload Firewall Dataset
============================================================================================================================================================================================================================

Upload file: listening_ports.log

Index: firewall\
Sourcetype: mac_firewall\
Host: MacBookPro\
\
The firewall index had already been created during the Splunk lab setup previous lab and was reused for the Firewall SOC Monitoring Lab. The listening_ports.log dataset was uploaded into the existing index for analysis**.\**

Description: The listening ports dataset was uploaded into Splunk Enterprise and assigned to the firewall index to support firewall monitoring and attack surface analysis.

\
\
\
\
Step 3 — Verify Ingestion
=======================================================================================================================================================================================

Search bar: index=firewall\
Verify that firewall data was successfully ingested into Splunk.\
\

\
Step 4 — Verify Event Count
===========================

Search bar:\
\
index=firewall\
\| stats count

Count firewall events stored in the index.\
\

**Step 5 — Review Listening Services**

Search:

index=firewall LISTEN

Purpose:

Identify services actively listening for network connections.\
\

# Step 6 — Review Open Ports

Search bar:

index=firewall\
\| table \_raw

Review exposed ports and listening services.

\
\
\
Step 7 — Search for SSH Port
=======================================================================================================================================================================================

Search bar: index=firewall 22

#### Determine whether SSH is exposed on the system.\
\
The search for port 22 returned no results, indicating that an SSH service was not identified in the collected firewall dataset. This does not necessarily mean that no services were exposed; other listening ports and network services may still be present and should be reviewed as part of the overall attack surface analysis.\
\
Search for Investigation:\
\
Search bar:\
index=firewall\
\| search 22 OR 443 OR 3306 OR 5000 OR 5900 OR 631 OR 7000\
\| table \_time host sourcetype \_raw\
\
\
\
**COMMAND**

The process or application name using the network connection.

splunkd\
Google\
mongod\
Creative

Helps identify which application owns a port or connection.

**PID (Process ID)**

Unique identifier assigned to a running process by the operating system.

splunkd 15367

Useful when investigating or terminating a process.

**FD (File Descriptor)**

Internal reference used by the operating system for open files or network sockets.

4u\
18u\
145u

**(u)** means the file/socket is open for reading and writing.

**TYPE**

Network protocol and IP version.

IPv4\
IPv6

Indicates whether the connection uses IPv4 or IPv6.

**DEVICE**

Internal operating-system identifier for the network socket.

0xb00512302fb47d4

Mostly useful for low-level OS troubleshooting rather than SOC investigations.

**NODE**

Indicates the protocol type.

TCP\
UDP

TCP = connection-oriented.\
UDP = connectionless.

**NAME**

The most important field for analysts.

Shows:

Local IP address\
Local port\
Remote IP address\
Remote port\
Connection state

TCP \*:8089 (LISTEN)

It means: Port 8089 is listening for incoming connections.

TCP 192.168.1.193:58609-\>150.171.109.73:443 (ESTABLISHED)

Mac is actively communicating with 150.171.109.73 on HTTPS port 443.

The firewall dataset was generated using lsof -i -P -n, which captures active network sockets and listening services. The output includes process names (COMMAND), process IDs (PID), file descriptors (FD), protocol types (TYPE), socket identifiers (DEVICE), transport protocols (NODE), and network connection details (NAME). These fields allow analysts to identify which applications are using network ports, what services are listening, and which remote systems are communicating with the endpoint.\
\
Step 8 — Search for Web Services
===================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================

Search bar: index=firewall 80 OR 443

Identify web-related services and encrypted communication ports.\
\
\
there is **1 event** for the file ( listening_ports.log )

1 file = 1 Splunk event\
231 lines inside that event

When searcheding: index=firewall 80 OR 443

Splunk found the one event because somewhere inside the file there are references to port **443**. It then displayed the entire event, which contains 231 lines.

The search indicates that **web-related services or HTTPS communications were present in the firewall dataset**.

Looking at output, there are entries such as:

192.168.1.193:58609 -\> 150.171.109.73:443 (ESTABLISHED)

and

192.168.1.193:62189 -\> 104.18.32.47:443

These indicate communication over: Port 443 = HTTPS / TLS encrypted traffic

which is commonly used by:

Web browsing\
Cloud services\
Google services\
Microsoft services\
Secure APIs

80 = HTTP (unencrypted web traffic) may not exist in this dataset.

Modern applications primarily use:

443 = HTTPS

instead of:

80 = HTTP

This query was used to identify web-related network activity within the firewall dataset by searching for ports 80 (HTTP) and 443 (HTTPS). The results showed active communications using port 443, indicating encrypted web traffic between the MacBook Pro and external systems. No significant HTTP (port 80) activity was observed, which is expected because most modern web services use HTTPS for secure communications. The findings demonstrate how firewall data can be used to identify web services and encrypted network activity.

Top of Form

Bottom of Form

**Step 9 — Search for Database Services**

Search: index=firewall 3306

Identify MySQL database exposure.\
\
\
The search for port 3306 returned no results, indicating that MySQL database service activity was not identified in the firewall dataset. This suggests that port 3306 was not present in the collected listening_ports.log snapshot. The absence of this result does not confirm that MySQL is never used on the system; it only means that MySQL was not detected in this specific dataset during the collection period.\
\
**Additional Firewall Investigation Queries\
\
. Search for Common Web Services**\
search: index=firewall (80 OR 443 OR 8080 OR 8000)\
Identify web servers, HTTPS services, web applications, and management interfaces.\
\
\
**. Search for File Sharing Services\**
Search: index=firewall (445 OR 139)\
Identify SMB/CIFS file-sharing services.

\
**. Search for Apple Services**

index=firewall (5000 OR 7000 OR 5353 OR 631)

Identify common macOS services such as AirPlay, mDNS/Bonjour, application services, and printing services.

\
**. Search for Established Connections\**
index=firewall ESTABLISHED

Identify active network communications.

\
**. Search for TCP Activity\**
index=firewall TCP\
Review TCP-based network services and connections.\
\
\
**. Search for UDP Activity**\
index=firewall UDP\
Review UDP-based services such as DNS, Bonjour, and discovery protocols.\
\
\
**. High-Risk Services\**
index=firewall (445 OR 139 OR 21 OR 23)\
Identify SMB, FTP, or Telnet services that may increase security risk.\
\
\
To further investigate the firewall dataset, additional searches were performed to identify listening services, active connections, web services, remote administration services, protocol activity, and application communications. These searches provided greater visibility into the system's attack surface and network behavior.

# Step 10 — Visualization

Search bar:\
index=firewall LISTEN\
\| stats count

Visualization: Single Value and Bar Chart\
Count listening services identified in the firewall dataset.\
\


Bottom of Form

\
Step 11 — Save Report
========================================================================================================================================================================================

Report Name: Firewall Listening Services Report

Description: This report identifies listening services and exposed ports discovered on the MacBook Pro.

\
Step 12 — Create Dashboard Panel
========================================================================================================================================================================================

Dashboard: Firewall SOC Monitoring Dashboard

Panel: Listening Ports Overview

Description: Displays listening services and exposed network ports identified in the firewall dataset.

\
Step 13 — Create Alert
========================================================================================================================================================================================

Search: index=firewall LISTEN

Alert Name: Listening Service Detection

Description: Detects services actively listening for incoming network connection.\
\
\
Step 14 — Detection Rule
========================================================================================================================================================================================

Search bar:\
\
index=firewall\
\| search LISTEN

Detection Name: Open Port Detection

### Description: Detects open ports and listening services that may increase system attack surface.\
\
\
This detection rule identified services in a LISTEN state, indicating open ports available for incoming connections. The results revealed listening services on ports 5000 and 7000, which contribute to the system's attack surface and should be monitored as part of firewall and network security operations.\
\
**Analyst Observation**

Based on the output:

TCP \*:7000 (LISTEN)\
TCP \*:5000 (LISTEN)

the most important findings are:

| **Port**        | **Typical Service**       |
|-----------------|---------------------------|
| 5000            | Application / Web Service |
| 7000            | AirPlay                   |
| 127.0.0.1:56357 | Localhost Only            |
| 127.0.0.1:45623 | Localhost Only            |
| 127.0.0.1:50983 | Localhost Only            |

Bottom of Form

\
Creative 31373 ... TCP 127.0.0.1:56357 (LISTEN)\
Creative 31373 ... TCP 127.0.0.1:45623 (LISTEN)\
Creative 31373 ... TCP 127.0.0.1:50983 (LISTEN)\
ControlCe ... TCP \*:7000 (LISTEN)\
ControlCe ... TCP \*:5000 (LISTEN)\
\
\
\
\
\
\
Investigation and Process analysis was performed through Mac terminal using the PIDs identified in the firewall dataset. The corresponding processes were no longer active at the time of investigation, indicating that the applications had terminated or restarted since the original data collection. The firewall snapshot nevertheless confirmed that the “ creative” process was listening on localhost-only ports, while the ControlCe process was listening on ports 5000 and 7000 across network interfaces. These findings demonstrate how firewall monitoring can identify applications responsible for exposing network services and help analysts assess potential attack surface exposure.\
\
Step 15 — Threat Hunting Query
==========================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================================

Search bar:\
\
index=firewall\
\| table \_time host sourcetype \_raw

Review listening services, open ports, and exposed applications for threat-hunting activities.

\
\
This lab used Splunk Enterprise to analyze firewall-related data, identify listening services and exposed ports, and create dashboards, reports, alerts, detections, and threat-hunting queries for attack surface monitoring.
