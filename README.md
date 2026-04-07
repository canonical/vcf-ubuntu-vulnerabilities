# Vulnerability Reports of Ubuntu images published on VMware Cloud Foundation's Solutions Catalog

This repository contains the results of a vulnerability scan performed on Ubuntu images published on VMware Cloud Foundation's Solutions Catalog. The scan uses VEX (Vulnerability Exploitability eXchange) data [provided by Canonical](https://github.com/canonical/ubuntu-security-notices/tree/main/vex/cve/).

We encourage our users to always use the latest Ubuntu images available on VCF's Solutions Catalog, as they are regularly updated with security patches and improvements. Vulnerabilites affecting older images may have been fixed in newer versions and can usually be mitigated by updating the packages to their latest versions:

```bash
sudo apt update
sudo apt upgrade -y
```

If the kernel has been updated, a reboot may be required to apply the security patches:

```bash
sudo reboot
```

# Repository Structure

You will find a directory for each "Solution" available on the Solutions Catalog. Each directory contains a file per image version with the list of vulnerabilities affecting that image version.

For example, `ubuntu-22-04-lts-jammy-2` contains the vulnerabiltiy reports for images published under this solution: https://vcf.broadcom.com/vsc/services/details/ubuntu-22-04-lts-jammy-2.

# Data structure

The CSV report contains the following columns:

 * **CVE ID**: The CVE identifier (e.g., CVE-2026-1234)
 * **Severity**: Severity level (e.g., critical, high, medium, low, unknown)
 * **Score**: CVSS score
 * **Image+Version**: Image version provided via --image-version
 * **Distro**: Ubuntu distribution provided via --ubuntu-version (e.g., jammy, noble)
 * **Package Name**: Affected package name
 * **Title**: CVE title
 * **URL**: Link to Ubuntu security notice
 * **Installed Version**: Version installed in the manifest
 * **Fixed Version**: Version that fixes the vulnerability
 * **Description**: CVE description
 * **Published Date**: Publication date of the CVE
 * **PURL**: Package URL in standard format

# Ubuntu Security Notices
 
Developers issue an Ubuntu Security Notice when a security issue is fixed in an [official Ubuntu package](https://packages.ubuntu.com/). You can find additional guidance for high-profile vulnerabilities in the [Ubuntu Vulnerability Knowledge Base](https://ubuntu.com/security/vulnerabilities) section.

To report a security vulnerability in an Ubuntu package, please [contact the Security Team](https://wiki.ubuntu.com/SecurityTeam/FAQ#Contact).
