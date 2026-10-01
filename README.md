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

### 5. Identifying the Ransomware Executable

The 14 process events from `AMFB-MACHINE` were reviewed by examining the `process_commandline` column from top to bottom.

During this review, a suspicious executable named `lockbyte_ransomer.exe` was identified on Anthony Davis's machine.

### KQL Query

```kql id="1s9d5c"
ProcessEvents
| where hostname == "AMFB-MACHINE"
| where process_commandline contains "ransomer"
```

### Finding

The query identified process activity containing `ransomer` in the command line. One suspicious executable was identified:

`lockbyte_ransomer.exe`

Host:

`AMFB-MACHINE`

User:

`andavis`

### Analysis

The presence of `lockbyte_ransomer.exe` provides a direct lead for the ransomware investigation. The executable name is consistent with the ransomware activity being investigated, but the process name alone does not establish maliciousness.

Further investigation should focus on the executable's hash, execution timestamp, process details, parent process, command line, and related file activity.

### Evidence

Screenshot of the KQL query and returned process event:

<img width="1366" height="768" alt="Screenshot_2026-10-01_20_59_47" src="https://github.com/user-attachments/assets/3e54dd00-c35d-4ba7-9600-1b2bae5b0fd4" />
