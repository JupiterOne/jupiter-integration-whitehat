# Whitehat

## Overview

JupiterOne provides a managed integration with Whitehat. The integration
connects directly to Whitehat APIs to obtain account metadata and analyze
resource relationships. Customers authorize access by creating an API key in
their target Whitehat account and providing that credential to JupiterOne.

## WhiteHat Security + JupiterOne Integration Benefits

- Visualize WhiteHat scans, cves, vulnerabilities, and findings in the JupiterOne graph.
- Map WhiteHat findings to a code repo, project, or application in your JupiterOne account.
- Monitor WhiteHat cves, findings, and vulnerabilities within the alerts app.
- Monitor changes to WhiteHat scans using JupiterOne alerts.

## How it Works

- JupiterOne periodically fetches WhiteHat scans and findings to update the graph.
- Write JupiterOne queries to review and monitor updates to the graph.
- Configure alerts to reduce the noise of findings.
- Configure alerts to take action when the JupiterOne graph changes.

## Requirements

- JupiterOne requires an API key to authenticate with WhiteHat.
- You must have permission in JupiterOne to install new integrations.

## Integration Instance Configuration

The integration is triggered by an event containing the information for a
specific integration instance.

To obtain the API token for a Whitehat account, sign in to Sentinel. Click the
"My Profile" button in the top right and then "API Key". Enter the account
password and copy the displayed API Key.

## Entities

The following entity resources are ingested when the integration runs:

| Whitehat Entity Resource | \_type : \_class of the Entity             |
| ------------------------ | ------------------------------------------ |
| Account                  | `whitehat_account` : `Account`             |
| Scan Type                | `whitehat_scan` : `Service`                |
| CVE                      | `cve` : `Vulnerability`                    |
| Vulnerability            | `whitehat_vulnerability` : `Vulnerability` |
| Finding                  | `whitehat_finding` : `Finding`             |

## Relationships

The following relationships are created/mapped:

### Intra-Instance

| From                     | Type           | To                       |
| ------------------------ | -------------- | ------------------------ |
| `whitehat_account`       | **HAS**        | `whitehat_scan`          |
| `whitehat_scan`          | **IDENTIFIED** | `whitehat_vulnerability` |
| `whitehat_vulnerability` | **EXPLOITS**   | `cwe`                    |
| `whitehat_finding`       | **IS**         | `whitehat_vulnerability` |

### Extra-Instance / Mapped

| From                           | Type        | To                                                                                                                                                                                                 |
| ------------------------------ | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CodeRepo/Project/Application` | **HAS/HAD** | `whitehat_finding` <br> Note: This is mapped automatically only when the name of the Whitehat Application the finding belongs to matches the name of a CodeRepo/Project/Application in JupiterOne. |
