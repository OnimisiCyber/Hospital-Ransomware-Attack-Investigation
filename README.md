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
