# Cloud SIEM Threat Hunting and Detection using Wazuh and AWS

## Project Summary
Built and operated a cloud based SIEM by deploying Wazuh on AWS EC2 and integrating a Windows Server 2022 endpoint. I configured secure communication, collected endpoint telemetry, enabled compliance and file integrity monitoring, enriched alerts with threat intelligence, mapped detections to the MITRE ATT&CK framework, and performed threat hunting using dashboards and event level analysis following a real SOC analyst workflow.

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

[Add screenshot: AWS EC2 instance and security group configuration]

## Endpoint Configuration
• Installed Wazuh agent on Windows Server 2022  
• Enrolled agent with the Wazuh Manager  
• Enabled secure log forwarding  
• Verified agent status and connectivity  

[Add screenshot: Wazuh agents dashboard]

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

[Add screenshot: Log collection or events view]

## Threat Detection Performed
• Authentication success and failure monitoring  
• Privilege escalation activity detection  
• Suspicious process and service execution  
• File modification and persistence behavior  
• Alerts mapped to MITRE ATT&CK techniques  

[Add screenshot: Alerts dashboard]

## Threat Hunting Workflow
• Used dashboards to identify abnormal patterns  
• Pivoted from alerts to raw event data  
• Analyzed timestamps, users, and host context  
• Followed structured SOC investigation methodology  

[Add screenshot: Threat hunting or events pivot view]

## MITRE ATT&CK Alignment
• Mapped detections to tactics and techniques  
• Demonstrated visibility across the attack lifecycle  
• Used framework driven validation during investigations  

[Add screenshot: MITRE ATT&CK mapping dashboard]

## File Integrity Monitoring
• Monitored critical Windows directories  
• Detected unauthorized file creation and changes  
• Generated real time alerts on modification events  

[Add screenshot: File integrity monitoring alerts]

## Configuration Assessment
• Applied CIS benchmark for Windows Server 2022  
• Identified security misconfigurations  
• Measured endpoint security posture  

[Add screenshot: Configuration assessment dashboard]

## Threat Intelligence Integration
• Integrated VirusTotal with Wazuh  
• Enriched alerts with file hash reputation data  
• Reduced false positives  
• Improved alert context and investigation accuracy  

[Add screenshot: VirusTotal enriched alert]

## Active Response
• Configured automated response rules  
• Blocked malicious source IP addresses  
• Validated response execution on the endpoint  

[Add screenshot: Active response execution]

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

## Screenshots and Evidence
• Architecture diagram  
• Wazuh dashboard alerts view  
• MITRE ATT&CK mapping view  
• VirusTotal enriched alert example  
• Agent and manager configuration files  
