# IamSub v1.1.0

![Banner](image.png)

## Overview
IamSub is a defensive cybersecurity tool designed for authorized subdomain enumeration and attack surface analysis. Unlike standard scrapers, IamSub focuses on the *context* of discovered assets, categorizing them by response codes and providing defensive insights into potential misconfigurations.

## Features
* **Passive Enumeration:** Queries Certificate Transparency logs.
* **Heuristic Permutation:** Generates potential "shadow IT" targets (dev, staging, etc.).
* **Liveness Verification:** Filters out dead DNS records.
* **Response Analysis:** Categorizes findings into `200` (Live), `403` (Forbidden), and `404` (Missing) buckets.
* **Automated Reporting:** Generates a Markdown summary with defensive recommendations.

## Installation

### Prerequisites
* Linux / macOS / WSL
* Python 3.6+

### Setup
1.  Clone the repository:
    ```bash
    git clone [https://github.com/yourusername/iamsub.git](https://github.com/yourusername/iamsub.git)
    cd iamsub
    ```
2.  Install dependencies:
    ```bash
    pip install requests colorama
    ```
3.  Make executable:
    ```bash
    chmod +x iamsub.py
    ```

## Usage

### Automatic Workflow
Run the full pipeline (Enumeration -> Liveness -> Analysis -> Reporting):
```bash
./iamsub.py example.com
