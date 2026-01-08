# Wazuh AWS SOC Threat Hunting Lab

## Project Summary
Built and operated a cloud based SIEM by deploying Wazuh on AWS EC2 and integrating a Windows Server 2022 endpoint. I configured secure communication, collected endpoint telemetry, enabled compliance and file integrity monitoring, enriched alerts with threat intelligence, mapped detections to the MITRE ATT&CK framework, and performed threat hunting using dashboards and event level analysis following a real SOC analyst workflow.
### Project Architecture  
  <p align="left">
  <img
    src="https://github.com/bikasha49/wazuh_aws_soc_threat_hunting_lab/blob/6d36870877a444f1de15f8f2afdf61cfeaefff43/screenshots/wazuh_architecture_diagram.png"
    width="60%">
</p>

## Project Objectives
• Build a cloud based SIEM environment  
• Detect real attack behavior on endpoints  
• Practice SOC analyst threat hunting workflow  
• Align detections with industry frameworks  

## Environment Setup
• Deployed Wazuh Manager on AWS EC2 Linux  
• Configured AWS security groups for controlled access  
• Enabled TLS encrypted agent to manager communication  
• Accessed Wazuh dashboard securely over HTTPS  
### Inbound Rules 
  <p align="left">
  <img
    src="https://raw.githubusercontent.com/bikasha49/wazuh_aws_soc_threat_hunting_lab/6d36870877a444f1de15f8f2afdf61cfeaefff43/screenshots/ec2_enstance_security_group_inbound_rules.png"
    width="60%">
</p>


## Endpoint Configuration
• Installed Wazuh agent on Windows Server 2022  
• Enrolled agent with the Wazuh Manager  
• Enabled secure log forwarding  
• Verified agent status and connectivity  
### Wazuh Manager 
<p align="left">
  <img
    src="https://github.com/bikasha49/wazuh_aws_soc_threat_hunting_lab/blob/6d36870877a444f1de15f8f2afdf61cfeaefff43/screenshots/agent_added_dash.png"
    width="60%">
</p>

## Tools and Technologies Used
• Wazuh SIEM and XDR  
• AWS EC2  
• Windows Server 2022  
• Wazuh Dashboard  
• VirusTotal Threat Intelligence API  

## Log Sources Collected
• Windows Security event logs  
• Windows System logs  
• Windows Application logs  
• Authentication and audit logs  
• File integrity monitoring events  
### Logs Collected 
<p align="left">
  <img
    src="https://github.com/bikasha49/wazuh_aws_soc_threat_hunting_lab/blob/6d36870877a444f1de15f8f2afdf61cfeaefff43/screenshots/threat_hunting-events.png"
    width="60%">
</p>

## Threat Detection Performed
• Authentication success and failure monitoring  
• Privilege escalation activity detection  
• Suspicious process and service execution  
• File modification and persistence behavior  
• Alerts mapped to MITRE ATT&CK techniques
### Mitre Att&ck Techniques 
<p align="left">
  <img
    src="https://github.com/bikasha49/wazuh_aws_soc_threat_hunting_lab/blob/6d36870877a444f1de15f8f2afdf61cfeaefff43/screenshots/miter_att%26ck_techniques.png"
    width="60%">
</p>

## Threat Hunting Workflow
• Used dashboards to identify abnormal patterns  
• Pivoted from alerts to raw event data  
• Analyzed timestamps, users, and host context  
• Followed structured SOC investigation methodology  

### Threat Hunting Events
<p align="left">
  <img
    src="https://github.com/bikasha49/wazuh_aws_soc_threat_hunting_lab/blob/6d36870877a444f1de15f8f2afdf61cfeaefff43/screenshots/threat_hunting-events.png"
    width="60%">
</p>

## MITRE ATT&CK Alignment
• Mapped detections to tactics and techniques  
• Demonstrated visibility across the attack lifecycle  
• Used framework driven validation during investigations  

### Analytical Value 
<p align="left">
  <img
    src="https://github.com/bikasha49/wazuh_aws_soc_threat_hunting_lab/blob/6d36870877a444f1de15f8f2afdf61cfeaefff43/screenshots/mitre_att%26ck_dashboard.png"
    width="60%">
</p>

## File Integrity Monitoring
• Monitored critical Windows directories  
• Detected unauthorized file creation and changes  
• Generated real time alerts on modification events  

### FIM Alerts 
<p align="left">
  <img
    src="https://github.com/bikasha49/wazuh_aws_soc_threat_hunting_lab/blob/6d36870877a444f1de15f8f2afdf61cfeaefff43/screenshots/file_integrity_monitor_dash_added_modified_deleted.png"
    width="60%">
</p>

## Configuration Assessment
• Applied CIS benchmark for Windows Server 2022  
• Identified security misconfigurations  
• Measured endpoint security posture  
### Benchmark 
<p align="left">
  <img
    src="https://github.com/bikasha49/wazuh_aws_soc_threat_hunting_lab/blob/6d36870877a444f1de15f8f2afdf61cfeaefff43/screenshots/configuration_assessment_dashboard.png"
    width="60%">
</p>

## Threat Intelligence Integration
• Integrated VirusTotal with Wazuh  
• Enriched alerts with file hash reputation data  
• Reduced false positives  
• Improved alert context and investigation accuracy  
### SIEM Integration 
<p align="left">
  <img
    src="https://github.com/bikasha49/wazuh_aws_soc_threat_hunting_lab/blob/6d36870877a444f1de15f8f2afdf61cfeaefff43/screenshots/virustotal_usage.png"
    width="60%">
</p>

## Active Response
• Configured automated response rules  
• Blocked malicious source IP addresses  
• Validated response execution on the endpoint  

## Security Best Practices Applied
• Masked API keys and sensitive configuration values  
• Sanitized IP addresses for public sharing  
• Followed least exposure principles  
• Clearly documented lab versus production considerations  

## What I Gained from This Project
• Hands on SIEM deployment experience  
• Real world threat detection and analysis skills  
• SOC analyst investigation workflow practice  
• Cloud security and networking knowledge  
• Threat intelligence integration experience  
• Confidence explaining alerts, risk, and mitigation  

## Project Value
• Demonstrates SOC readiness  
• Shows practical detection and response capability  
• Shows cloud security awareness  
• Shows professional documentation and reporting skills  

## Screenshots and Evidence 👉 *[Click here](https://github.com/bikasha49/wazuh_aws_soc_threat_hunting_lab/tree/main/screenshots)*

### 🌐 Let's Connect
<a href="https://www.linkedin.com/in/bikasha-gurung">
  <img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="Connect on LinkedIn" />
</a>
