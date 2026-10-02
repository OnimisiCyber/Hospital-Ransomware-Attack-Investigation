# Jojo Hospital Ransomware Investigation

## Overview

This investigation examines a ransomware attack targeting Jojo Hospital using KC7Cyber investigation data and Kusto Query Language (KQL).

The investigation focuses on identifying the scope of the ransomware activity, affected systems, encrypted files, user and process activity, and other indicators associated with the attack.

According to the investigation scenario, the ransomware group identified as LOCKBYTE demanded $2 million. The attackers also threatened patients with the release of sensitive information, including Social Security numbers, medical information, and health history, unless a $10,000 payment was made.

## Investigation Objective

The objectives of this investigation are to:

* Determine the scope of the ransomware attack.
* Identify files affected by encryption activity.
* Identify affected systems and users.
* Establish the timeline of the attack.
* Investigate processes and accounts associated with the attack.
* Identify indicators of compromise.
* Investigate possible data theft before the ransomware activity.
* Document findings using KQL and supporting evidence.

## Investigation Log

### 1. Identifying Encrypted Files

The first step was to determine how many file creation events were associated with files using the `.encrypted` extension.

### KQL Query

```kql
FileCreationEvents
| where filename endswith ".encrypted"
| count
```

### Result

The query returned:

`6,420`

This indicates that 6,420 file creation events matched the `.encrypted` filename condition.

### Analysis

The result shows significant encryption-related activity within the dataset. Since the query counts events rather than distinct filenames, the result is documented as 6,420 matching file creation events.

### Evidence

Screenshot of the KQL query and returned result:

`<img width="1366" height="768" alt="Screenshot_2026-10-01_16_09_19" src="https://github.com/user-attachments/assets/c064be14-a9a2-4bbd-bb10-d54d1b501359" />

### 2. Identifying Unique Hosts Affected

After identifying 6,420 encrypted-file events, the next step was to determine how many unique hosts recorded file encryption activity.

### KQL Query

```kql
FileCreationEvents
| where filename endswith ".encrypted"
| distinct hostname
| count
```

### Result

The query returned `[321]` unique hostnames.

### Analysis

This result shows the number of unique hosts where files with the `.encrypted` extension were created. This helps determine the spread of the ransomware activity across the hospital environment.

### Evidence

Screenshot of the KQL query and returned result:

<img width="1366" height="768" alt="Screenshot_2026-10-01_16_37_46 (copy 1)" src="https://github.com/user-attachments/assets/5100897d-7e20-4dba-a597-de1c29e2ca32" />

### 3. Identifying the SHA-256 Hash of the Ransom Note

The next step was to identify the SHA-256 hash associated with the ransom note created during the ransomware attack.

### KQL Query

```kql
FileCreationEvents
| where filename == "We_Have_Your_Data_Pay_Up.txt"
```

### Result

The SHA-256 hash identified for the ransom note was:

`97c348e95c8a8aeb8808f76434d73a92bbcb6b4586788365762b22624990b018` which is under this Path: C:\\Users\\andavis\\Documents\\We_Have_Your_Data_Pay_Up.txt i the system 

### Analysis

The identified SHA-256 hash serves as a file indicator of compromise (IOC) associated with the ransom note `We_Have_Your_Data_Pay_Up.txt`.

This hash will be useful for searching other events and determining whether the same ransom note appeared on multiple hosts during the attack.

### Evidence

Screenshot of the KQL query and result:

`<img width="1366" height="768" alt="Screenshot_2026-10-01_16_44_44" src="https://github.com/user-attachments/assets/62d90a9b-2249-437f-8f7f-46213ac02672" />

Checking to know how many hosts (machines) was this ransom file seen 


### KQL Query

```kql
FileCreationEvents
| where filename == "We_Have_Your_Data_Pay_Up.txt"
| count
```

### Result

The query returned `[1]` unique host (Machine)



### Evidence

Screenshot of the KQL query and result:

<img width="1366" height="768" alt="Screenshot_2026-10-01_16_55_29" src="https://github.com/user-attachments/assets/0f16ee3e-c441-4ed3-8265-4e12a504131d" />

### 4. Investigating Process Activity on the Affected Host

The ransom note `We_Have_Your_Data_Pay_Up.txt` was identified on only one machine, `AMFB-MACHINE`, belonging to Anthony Davis with the username `andavis`.

Because the ransom note appeared on this host, the next step was to investigate process activity on the machine during the period surrounding the ransomware activity.

### KQL Query

```kql
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-06-17) .. datetime(2024-06-18))
| count
```

### Result

The query returned 14 process events.

### Analysis

A total of 14 process events were recorded on `AMFB-MACHINE` between June 17 and June 18, 2024.

The presence of process activity during the same period as the ransomware investigation makes this host a key system for further analysis. The next step is to examine the individual process events to identify the processes executed, their timestamps, associated users, command lines, and any suspicious activity.

### Evidence

Screenshot of the KQL query and result:

<img width="1366" height="768" alt="Screenshot_2026-10-01_20_51_21" src="https://github.com/user-attachments/assets/6db0a3ae-282e-4af4-a71b-8b4f63ca3059" />

### 5. Identifying and Tracking the Ransomware Executable

The 14 process events from `AMFB-MACHINE` were reviewed by examining the `process_commandline` column from top to bottom.

During this review, a suspicious executable named `lockbyte_ransomer.exe` was identified on Anthony Davis's machine.

### KQL Query

```kql id="8n2xqk"
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where process_commandline contains "ransomer"
```

### Finding

The investigation identified the following suspicious executable:

`lockbyte_ransomer.exe`

Host:

`AMFB-MACHINE`

User:

`andavis`

The investigation also showed that the ransomware executable was copied to a network share and given a new filename:

`spread_ransomware.exe`

The observed path was:

`C:\Users\andavis\Downloads\lockbyte_ransomer.exe\jojos-hospital.org\shared\spread_ransomware.exe`

### Analysis

The evidence shows activity involving `lockbyte_ransomer.exe` on Anthony Davis's machine and a subsequent copy of the executable to the hospital's network share under the name `spread_ransomware.exe`.

The filename change is important because searching only for `lockbyte_ransomer.exe` would miss the renamed copy. The network-share location also provides a lead for investigating whether the ransomware was distributed to other systems through the shared location.

Further investigation should examine the network share activity, the renamed executable, other hosts accessing the share, and the processes associated with `spread_ransomware.exe`.

### Evidence

Screenshot of the KQL query and returned process event:

<img width="1366" height="768" alt="Screenshot_2026-10-01_20_59_47" src="https://github.com/user-attachments/assets/3e54dd00-c35d-4ba7-9600-1b2bae5b0fd4" />


### 6. Identifying Patient Data Collection, Exfiltration, and Cleanup

The next step was to review the distinct process command lines executed on `AMFB-MACHINE` during the investigation period.

### KQL Query

```kql id="h9w4pc"
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where timestamp between (datetime(2024-06-17) .. datetime(2024-06-18))
| distinct process_commandline
```

### Finding

The command-line activity revealed a suspicious executable named:

`patient_data_exporter.exe`

The executable was used with an `/export` parameter to collect patient data from directories on the hospital server and create ZIP archives.

Three exported archives were identified:

`patient_data_1.zip`

Source:

`\\jojos-hospital-server\important_data\patient_records`

`patient_data_2.zip`

Source:

`\\jojos-hospital-server\important_data\archive\patient-records`

`patient_data_3.zip`

Source:

`\\jojos-hospital-server\important_data\old-patient-data`

Example command line:

```text id="8y1hjp"
C:\Users\andavis\Downloads\patient_data_exporter.exe /export C:\Users\andavis\Documents\patient_data_3.zip /source \\jojos-hospital-server\important_data\old-patient-data
```

### Data Exfiltration

After the patient data was collected and compressed into ZIP archives, the investigation showed that the stolen data was sent to the suspicious external domain:

`secure-health-access.com` which is also the same domain where the malicious executable 
`patient_data_exporter.exe` was downloaded from

Each of the three ZIP files was associated with this destination.

### Evidence of Cleanup Activity

The investigation also identified a command used to delete the exported ZIP archives:

```text id="4j7p3m"
cmd.exe /c del C:\Users\andavis\Documents\patient_data_*.zip
```

The wildcard `patient_data_*.zip` targets the exported patient-data archives stored in Anthony Davis's Documents directory.

This activity occurred after the data collection and transfer activity and is consistent with an attempt to remove the locally stored copies of the collected data.

### Analysis

The evidence shows a sequence involving patient-data collection, archive creation, transmission to an external destination, and subsequent deletion of the ZIP archives from the local machine.

The observed sequence is:

1. Patient data was collected from hospital server directories.
2. The collected data was compressed into three ZIP archives.
3. The ZIP archives were then moved  to `secure-health-access.com`.
4. A command was used to delete the local ZIP archives.

The cleanup command provides an additional investigation lead because deleting the local archives might have reduced the amount of evidence available on the compromised machine.


### Evidence

Screenshot of the KQL query and returned command-line activity:


<img width="1366" height="768" alt="Screenshot_2026-10-01_21_34_13" src="https://github.com/user-attachments/assets/ccc9f72f-f914-46e8-8f44-cb38b69ee65d" />

### 7. Investigating the Malicious Domain Infrastructure

After identifying `secure-health-access.com` as the destination associated with the stolen patient-data archives, the next step was to investigate the domain's infrastructure.

The first objective was to identify the IP addresses associated with the domain.

### 7.1 Domain to IP Association

### KQL Query

```kql id="6w2rqa"
PassiveDns
| where domain == "secure-health-access.com"
```

### Finding

The query showed that `secure-health-access.com` resolved to two IP addresses:

`203.0.113.1`

`203.0.113.2`

### Analysis

The domain's association with two IP addresses provides additional infrastructure indicators for the investigation. These IP addresses can be used to search for other domains associated with the same infrastructure.

### Evidence

Screenshot of the domain-to-IP Passive DNS query and result:
<img width="1366" height="768" alt="Screenshot_2026-10-01_22_07_29" src="https://github.com/user-attachments/assets/33786811-018d-4f7c-ae11-c82155855b08" />
### 7.2 Identifying Other Domains Sharing the Infrastructure

The next step was to investigate whether other domains were associated with the identified IP addresses.

### KQL Query

```kql id="3f7mvp"
PassiveDns
| where ip in ("203.0.113.1", "203.0.113.2")
```

### Finding

The query identified another domain associated with the infrastructure:

`emr-help.net`

The domain was associated with:

`203.0.113.1`

### Analysis

The discovery of `emr-help.net` on the same IP infrastructure as `secure-health-access.com` provides another domain for investigation.

### Evidence

Screenshot of the IP-to-domain Passive DNS query and result:

<img width="1366" height="768" alt="Screenshot_2026-10-01_22_09_37" src="https://github.com/user-attachments/assets/5b24792b-e29a-4979-92d8-d7c662a914b9" />

### 8. Investigating Inbound Requests from the Identified IP Addresses

After identifying `203.0.113.1` and `203.0.113.2` as IP addresses associated with `secure-health-access.com`, the next step was to determine whether these IPs made requests to Jojo Hospital's web infrastructure.

### 8.1 Identifying Inbound Requests

### KQL Query

```kql id="v7c1pk"
InboundNetworkEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
```

### Result

The query returned 37 inbound network events originating from the two identified IP addresses.

### Analysis

The result shows that the two IP addresses associated with the suspicious domain generated 37 inbound requests to Jojo Hospital's network.

This provided a basis for examining the specific URLs requested by the source IPs.

### Evidence

Screenshot of the inbound network query and result:

<img width="1366" height="768" alt="Screenshot_2026-10-01_22_24_38" src="https://github.com/user-attachments/assets/b90892bb-505a-4f12-a5fe-f36574661d98" />

### 8.2 Investigating Requests Containing "Bypass"

The next step was to search the inbound requests for URLs containing the term `bypass`.

### KQL Query

```kql id="2k8xvd"
InboundNetworkEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
| where url has "bypass"
```

### Finding

The query identified a request to the Jojo Hospital website containing a search for:

`how to bypass security JoJo's Hospital`

Observed URL:

`https://jojoshospital.org/search=how+to+bypass+security+JoJo%27s+Hospital`

### Analysis

The request shows that a source IP associated with the previously identified suspicious infrastructure accessed Jojo Hospital's website and searched for information related to bypassing the hospital's security.



### Evidence

Screenshot of the KQL query and returned request:

<img width="1366" height="768" alt="Screenshot_2026-10-01_22_26_39" src="https://github.com/user-attachments/assets/681bc4cf-9196-44c4-b7fe-ba9018614776" />

### 9. Investigating Account Authentication from the Suspicious IPs

After identifying inbound requests from `203.0.113.1` and `203.0.113.2`, the next step was to determine whether either IP address was used to authenticate to an account within the hospital environment.

### 9.1 Identifying Authentication Activity

### KQL Query

```kql id="q6m1vz"
AuthenticationEvents
| where src_ip in ("203.0.113.1", "203.0.113.2")
```

### Finding

The query identified one authentication event originating from:

`203.0.113.1`

The authentication occurred on:

Hostname:

`MAIL-SERVER01`

The host was later associated with the user:

`andavis`

User:

`Anthony Davis`

### Analysis

The authentication event links the suspicious IP address `203.0.113.1` to an authenticated session involving `MAIL-SERVER01`.

The hostname was then investigated to determine which user's device or account was associated with the system. The result identified `andavis`, the same username previously associated with `AMFB-MACHINE` and the ransomware investigation.

This creates an important connection between the suspicious infrastructure and Anthony Davis's account.

### Evidence

Screenshot of the authentication query and result:

<img width="1366" height="768" alt="Screenshot_2026-10-01_22_41_41" src="https://github.com/user-attachments/assets/92a3d41a-2a1c-45f5-9bb7-3d5c918dc075" />

### 10. Investigating a Lookalike Malicious Domain

The investigation identified a possible phishing or malvertising-related activity involving a domain designed to resemble the legitimate Raising Cane's website.

The legitimate domain is:

`raisingcanes.com`

The suspicious lookalike domain identified in the investigation is:

`raisinkanes.com`

The domains use similar names, which could make the malicious domain harder for staff to distinguish from the legitimate website.

### 10.1 Identifying Requests to the Malicious Domain

The first step was to determine how many outbound network requests were made to the suspicious domain.

### KQL Query

```kql id="r8c2nf"
OutboundNetworkEvents
| where url contains "raisinkanes"
| count
```

### Result

The query returned:

`26`

This represents 26 outbound network events matching `raisinkanes`.

### Evidence

Screenshot of the KQL query and result:

<img width="1366" height="768" alt="Screenshot_2026-10-02_20_53_34" src="https://github.com/user-attachments/assets/2b0eaf63-8e45-46ad-8bc3-b4953dda4c48" />

### 10.2 Identifying Unique Staff Sources

The next step was to determine how many unique source IPs accessed the suspicious domain.

### KQL Query

```kql id="n4w7ks"
OutboundNetworkEvents
| where url contains "raisinkanes"
| distinct src_ip
```

### Result

The query returned:

`24`

This means 24 unique source IPs generated outbound requests matching `raisinkanes`.

### Evidence

Screenshot of the KQL query and result:

<img width="1366" height="768" alt="Screenshot_2026-10-02_20_55_53" src="https://github.com/user-attachments/assets/48457282-0542-476f-b089-097705984eac" />

### Analysis

The investigation identified 26 outbound requests from 24 unique source IPs to the lookalike domain `raisinkanes.com`.

The difference between the two numbers indicates that some source IPs generated more than one matching request.


### 11. Investigating the Redirect Chain and Malicious Files

After identifying 26 requests from 24 unique source IPs to the lookalike domain `raisinkanes.com`, the investigation continued by examining the redirects associated with the domain.

### 11.1 Identifying Redirect Activity

The following query was used to identify outbound requests containing redirect activity.

### KQL Query

```kql id="k2v9rx"
OutboundNetworkEvents
| where url has "redirect"
```

### Finding

The investigation identified redirects from the malicious lookalike domain to:

`nothing-to-see-here.net`

Further investigation also identified a redirect to:

`totally-legit-domain.com`

### 11.2 Investigating the Redirect Destination

The results were narrowed to requests containing `totally` to investigate activity associated with the second redirect destination.

### KQL Query

```kql id="p5c7yd"
OutboundNetworkEvents
| where url has "totally"
```

### Finding

The investigation showed that `totally-legit-domain.com` redirected users to a Microsoft Word document named:

`Raisin_Kane_Promo_Offer.docx`

Full URL:

`https://totally-legit-domain.com/published/Raisin_Kane_Promo_Offer.docx`

The investigation also identified redirects from the same domain to a PDF file named:

`Raisin_Kane_Free_Meal_Voucher.pdf`

### Analysis

The redirect chain shows that requests to the lookalike domain led users through additional domains before reaching files presented as promotional or free-meal offers.

At this stage, the files should be treated as suspicious artifacts rather than confirmed malware. Further investigation should examine the file hashes, download events, affected hosts, users who accessed the files, and any process or execution activity following the downloads.

### Redirect Chain

`raisinkanes.com`

↓

`nothing-to-see-here.net`

↓

`totally-legit-domain.com`

↓

`Raisin_Kane_Promo_Offer.docx`

or

`Raisin_Kane_Free_Meal_Voucher.pdf`

### Evidence

Screenshot of the redirect query and results:

<img width="1366" height="768" alt="Screenshot_2026-10-02_21_16_43" src="https://github.com/user-attachments/assets/c28380e0-d487-422e-a2f0-51fc42e5406c" />

Screenshot showing the `totally-legit-domain.com` activity and file redirects:

<img width="1366" height="768" alt="Screenshot_2026-10-02_21_20_39" src="https://github.com/user-attachments/assets/1566f7af-c841-4677-b64e-de57fec48b9c" />

### 12. Investigating the Malicious Document on Endpoint Systems

After identifying `Raisin_Kane_Promo_Offer.docx` in the redirect chain, the next step was to determine whether the document was downloaded onto any hospital systems.

### 12.1 Identifying Systems with the Document

### KQL Query

```kql id="f3n8wx"
FileCreationEvents
| where filename == "Raisin_Kane_Promo_Offer.docx"
```

### Result

The query identified the document on:

`24 systems`

The first system examined was:

Hostname:

`RQJQ-MACHINE`

The file was downloaded through Google Chrome.

### Evidence

Screenshot of the file creation query and result:

`[Add Screenshot Here]`

### 12.2 Investigating Activity on RQJQ-MACHINE

The hostname was investigated to examine the activity surrounding the document download.

### KQL Query

```kql id="c7v2mz"
FileCreationEvents
| where hostname == "RQJQ-MACHINE"
```

### Finding

The investigation showed that after `Raisin_Kane_Promo_Offer.docx` was downloaded, an executable named:

`cobaltstrike.exe`

was downloaded approximately 27 seconds later.

### Analysis

The short time interval between the document download and the subsequent `cobaltstrike.exe` download makes the sequence relevant to the investigation.

The timing alone does not establish that the document caused the executable download. Further process and network evidence is required to establish the relationship between the two events.

### Evidence

Screenshot showing the document and `cobaltstrike.exe` file creation events:

<img width="1366" height="768" alt="Screenshot_2026-10-02_21_41_34" src="https://github.com/user-attachments/assets/2e06ebef-26c1-4d85-87ea-7d90f689a633" />

### 12.3 Investigating Execution of the Downloaded Document

The next step was to examine process activity on `RQJQ-MACHINE` around the time of the document activity.

### KQL Query

```kql id="w6p4kr"
ProcessEvents
| where hostname == "RQJQ-MACHINE"
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-02))
| where process_commandline contains "Raisin_Kane_Promo_Offer"
```

### Finding

The query identified the following command line:

```text
C:\Program Files\Microsoft Office\Office16\WINWORD.EXE" "C:\Users\evbrowne\Downloads\Raisin_Kane_Promo_Offer.docx
```

The command line shows that Microsoft Word was used to open the downloaded document from the user's Downloads directory.

User:

`evbrowne`

Host:

`RQJQ-MACHINE`

### Analysis

The evidence establishes the following sequence on `RQJQ-MACHINE`:

1. `Raisin_Kane_Promo_Offer.docx` was downloaded through Chrome.
2. Microsoft Word opened the document from the user's Downloads directory.
3. Approximately 27 seconds later, `cobaltstrike.exe` was downloaded.


### Evidence

Screenshot of the process command-line query and result:

<img width="1366" height="768" alt="Screenshot_2026-10-02_22_01_25" src="https://github.com/user-attachments/assets/e9bed9c8-c263-4ee8-9878-659c62e1e53e" />

### 12.4 Identifying Network Indicators Associated with Cobalt Strike

The next step was to investigate the command-line activity associated with `cobaltstrike.exe` on `RQJQ-MACHINE` and identify additional indicators of compromise.

### KQL Query

```kql id="q4m8vz"
ProcessEvents
| where hostname == "RQJQ-MACHINE"
| where timestamp between (datetime(2024-05-01) .. datetime(2024-05-02))
| where process_commandline contains "cobaltstrike"
| distinct process_commandline
```

### Finding

The process command-line activity revealed a network connection to:

IP address:

`93.238.22.122`

Port:

`50050`

The connection was associated with the `cobaltstrike` process.

### Analysis

The IP address and port provide additional network indicators for the investigation.

The observed activity shows `cobaltstrike.exe` associated with a connection to `93.238.22.122` over port `50050`.

Port `50050` is commonly associated with Cobalt Strike Beacon communication, so this finding warrants further investigation of the destination IP, network events, timestamps, and other hosts communicating with the same infrastructure.


### IOC

IP Address: `93.238.22.122`

Port: `50050`

Associated Process: `cobaltstrike.exe`

Host: `RQJQ-MACHINE`

### Evidence

Screenshot of the KQL query showing the Cobalt Strike command line and network indicator:

<img width="1366" height="768" alt="Screenshot_2026-10-02_22_09_08" src="https://github.com/user-attachments/assets/f7843ed0-e792-4884-80ca-8f3a43d7d4f2" />

### 12.5 Investigating Discovery Activity

After identifying `cobaltstrike.exe` and the associated connection to `93.238.22.122:50050`, the next step was to investigate whether the compromised host showed signs of system or network discovery activity.

### KQL Query

```kql id="z5r8kc"
ProcessEvents
| where hostname == "RQJQ-MACHINE"
| where timestamp between (datetime(2024-05-02) .. datetime(2024-05-04))
| distinct process_commandline
```

### Finding

The query identified 6 discovery-related commands executed on `RQJQ-MACHINE`.

The first identified command was:

`systeminfo`

The `systeminfo` command is used to retrieve information about the Windows system, including operating system and system configuration details.

### Analysis

The presence of 6 discovery commands shows that additional reconnaissance activity occurred on `RQJQ-MACHINE` after the earlier Cobalt Strike activity.

The first identified command, `systeminfo`, indicates an attempt to gather information about the compromised system.

### Evidence

Screenshot of the KQL query and returned discovery commands:

<img width="1366" height="768" alt="Screenshot_2026-10-02_22_20_40" src="https://github.com/user-attachments/assets/baa496b9-8611-4e55-9e9f-e1986829c58b" />

### Investigation Status

Current findings on `RQJQ-MACHINE` include:

* `Raisin_Kane_Promo_Offer.docx` downloaded through Chrome.
* The document was opened with Microsoft Word.
* `cobaltstrike.exe` was downloaded approximately 27 seconds later.
* `cobaltstrike.exe` was associated with `93.238.22.122:50050`.
* 6 discovery-related commands were identified.
* The first identified discovery command was `systeminfo`.



