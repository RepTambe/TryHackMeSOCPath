# TryHackMeSOCPath
Soc Analyst Path notes from THM


# Splunk: Basics:::


Splunk has three main components, namely Forwarder, Indexer, and Search Head. These components are explained below:


Forwader

![forwarder](https://github.com/RepTambe/TryHackMeSOCPath/assets/56054621/14f1e9bd-fbbd-4bbf-8e18-7a724c95face)

Starting with the basic searches:

1. Upload the data attached to this task and create an index "VPN_Logs". How many events are present in the log file?
  Just a simple upload and a check of events got me the answer at 2862.

  
2. What is the number of events that originated from all countries except France?

    source="VPNlogs.json" Source_Country!=France
   
    Checking the total event number gives me the answer at 2814




# Incident handling with Splunk:::
This room covers an incident Handling scenario using Splunk. An incident from a security perspective is "Any event or action, that has a negative consequence on the security of a user/computer or an organization is considered a security incident." Below are a few of the events that would negatively affect the environment when they occurred:

Crashing the system
Execution of an unwanted program
Access to sensitive information from an unauthorized user
A Website being defaced by the attacker
The use of USB devices when there is a restriction in usage is against the company's policy
Learning ObjectiveAnalyst standing with magnifying glass
Learn how to leverage OSINT sites during an investigation
How to map Attacker's activities to Cyber Kill Chain Phases
How to utilize effective Splunk searches to investigate logs
Understand the importance of host-centric and network-centric log sources

As an Incident Handler / SOC Analyst, we would aim to know the attackers' tactics, techniques, and procedures. Then we can stop/defend/prevent against the attack in a better way. The Incident Handling process is divided into four different phases. Let's briefly go through each phase before jumping into the incident, which we will be going through in this exercise.


1. Preparation

The preparation phase covers the readiness of an organization against an attack. That means documenting the requirements, defining the policies, incorporating the security controls to monitor like EDR / SIEM / IDS / IPS, etc. It also includes hiring/training the staff.



2. Detection and Analysis

The detection phase covers everything related to detecting an incident and the analysis process of the incident. This phase covers getting alerts from the security controls like SIEM/EDR investigating the alert to find the root cause. This phase also covers hunting for the unknown threat within the organization.



3. Containment, Eradication, and Recovery

This phase covers the actions needed to prevent the incident from spreading and securing the network. It involves steps taken to avoid an attack from spreading into the network, isolating the infected host, clearing the network from the infection traces, and gaining control back from the attack.


4. Post-Incident Activity / Lessons Learnt
This phase includes identifying the loopholes in the organization's security posture, which led to an intrusion, and improving so that the attack does not happen next time. The steps involve identifying weaknesses that led to the attack, adding detection rules so that similar breach does not happen again, and most importantly, training the staff if required.


### Cyber Kill Chain Scenario

Scenario

A Big corporate organization Wayne Enterprises has recently faced a cyber-attack where the attackers broke into their network, found their way to their web server, and have successfully defaced their website http://www.imreallynotbatman.com. Their website is now showing the trademark of the attackers with the message YOUR SITE HAS BEEN DEFACED  as shown below. They have requested "US" to join them as a Security Analyst and help them investigate this cyber attack and find the root cause and all the attackers' activities within their network.

The good thing is, that they have Splunk already in place, so we have got all the event logs related to the attacker's activities captured. We need to explore the records and find how the attack got into their network and what actions they performed.
This Investigation comes under the Detection and Analysis phase.

### Reconnaissance 

Reconnaissance is an attempt to discover and collect information about a target. It could be knowledge about the system in use, the web application, employees or location, etc.


We will start our analysis by examining any reconnaissance attempt against the webserver imreallynotbatman.com. From an analyst perspective, where do we first need to look? If we look at the available log sources, we will find some log sources covering the network traffic, which means all the inbound communication towards our web server will be logged into the log source that contains the web traffic. Let's start by searching for the domain in the search head and see which log source includes the traces of our domain.

Search Query: index=botsv1 imreallynotbatman.com

Search Query explanation: We are going to look for the event logs in the index "botsv1" which contains the term imreallynotbatman.com
