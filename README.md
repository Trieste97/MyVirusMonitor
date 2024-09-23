# Antivirus Monitor: A tool for measuring incident response times

## 📚 Overview
This project is a thesis work that focuses on the design and implementation of a system called Antivirus Monitor. The main objective is to monitor files, preferably infected with viruses, and generate insightful statistics on both the files and antivirus performance. The system leverages data from VirusTotal, a popular malware detection platform, to provide statistics on false positives, detection times, and possible correlations between different antivirus software. This tool is particularly useful for understanding the efficiency and accuracy of antivirus software in detecting and responding to new malware threats.  

## 📊 How It Works
The system operates in four main phases:
- File collection: files are collected either by uploading through a web interface (static) or by analyzing comments in VirusTotal's community section (dynamic).
- File analysis: files are submitted to VirusTotal for scanning and the system collects reports on the file's status over time.
- Statistics calculation: various statistics such as detection rates, false positives, and antivirus reaction times are calculated.
- Visualization: the collected data is visualized using graphs and tables for easy interpretation.

## 🛠️ Technologies Used
### Backend
- Python3: used for data collection, processing, and communication with VirusTotal API.
- Flask: provides the HTTP routing for the web interface (GET/POST methods).
- MySQL: a relational database for storing file scan results and statistics.
- Apache2: the web server that serves the web pages to the clients.

### Frontend
- CanvasJS: JavaScript library used for creating interactive graphs and charts for data visualization.

## 📂 Database Structure
The system uses a relational database (MySQL) with the following key tables:

- File: contains all monitored files with fields like id, name, resource_id (SHA256), and next_scan (next scan date).
- AntiVirus: contains the names of antivirus software.
- VirusDetected: records when an antivirus identifies a file as malware, including file_id, av_name, and detect_date.
- FileProcessed: logs the files processed by each antivirus.
- FalsePositive: captures instances where a file was initially marked as malware but later found to be benign.

## 📈 Types of Statistics Calculated
General Statistics:
- Percentage of files detected
- Percentage of false positives
- Percentage of files processed

Time-Based Statistics:
- Calculates the average reaction time for each antivirus to identify malware.

Signature Copying Analysis:
- Attempts to identify which antivirus products might be copying virus signatures from others.

Cross-Correlation Analysis:
- Analyzes correlations between antivirus detections over time.
