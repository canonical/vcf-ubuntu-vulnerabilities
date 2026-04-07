# Vulnerability Reports of Ubuntu images published on VMware Cloud Foundation's Catalog.

This repository contains the results of a vulnerability scan performed on Ubuntu images published on VMware Cloud Foundation's Catalog. The scan uses VEX (Vulnerability Exploitability eXchange) data [provided by Canonical](https://github.com/canonical/ubuntu-security-notices/tree/main/vex/cve/).

We encourage our users to always use the latest Ubuntu images available on VMware Cloud Foundation's Catalog, as they are regularly updated with security patches and improvements. Vulnerabilites affecting older images may have been fixed in newer versions and can usually be mitigated by updating the packages to their latest versions:

```bash
sudo apt update
sudo apt upgrade -y
```

If the kernel has been updated, a reboot may be required to apply the security patches:

```bash
sudo reboot
```

# Ubuntu Security Notices
 
Developers issue an Ubuntu Security Notice when a security issue is fixed in an [official Ubuntu package](https://packages.ubuntu.com/). You can find additional guidance for high-profile vulnerabilities in the [Ubuntu Vulnerability Knowledge Base](https://ubuntu.com/security/vulnerabilities) section.

To report a security vulnerability in an Ubuntu package, please [contact the Security Team](https://wiki.ubuntu.com/SecurityTeam/FAQ#Contact).
