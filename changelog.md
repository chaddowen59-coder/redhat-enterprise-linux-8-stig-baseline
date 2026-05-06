# Changelog: RHEL 8 STIG Baseline (v2r7 vs. previous)

This document outlines the differences between the new `redhat-enterprise-linux-8-stig-baseline-v2r7` repository and the previous `redhat-enterprise-linux-8-stig-baseline`.

## Overview
- **XCCDF Benchmark Update**: The v2r7 manual XCCDF benchmark (`U_RHEL_8_STIG_V2R7_Manual-xccdf.xml`) was introduced in the new baseline.
- **Controls Update**: The new baseline introduces 9 new controls and removes 10 obsolete controls. All other baseline files, inputs, and controls remain identical between the two repositories.

## Added Controls
The following 9 controls were **added** in the v2r7 baseline:
- **SV-272482**: The RHEL 8 SSH client must be configured to use only DOD-approved...
- **SV-272483**: The RHEL 8 SSH client must be configured to use only DOD-approved...
- **SV-272484**: RHEL 8 must elevate the SELinux context when an administrator calls the sudo command.
- **SV-274877**: RHEL 8 must audit any script or executable called by cron as root or by any privileged user.
- **SV-279929**: RHEL 8 must automatically exit interactive command shell user sessions after 10 minutes of inactivity.
- **SV-279930**: RHEL 8 IP tunnels must use FIPS 140-3-approved cryptographic algorithms.
- **SV-279931**: RHEL 8 must implement DOD-approved encryption in the bind package.
- **SV-279932**: RHEL 8 cryptographic policy must not be overridden.
- **SV-279933**: RHEL 8 must have the crypto-policies package installed.

## Removed Controls
The following 10 controls were **removed** from the previous baseline:
- **SV-230254**: The RHEL 8 operating system must implement DoD-approved encryption in...
- **SV-230255**: The RHEL 8 operating system must implement DoD-approved TLS encryption
- **SV-230256**: The RHEL 8 operating system must implement DoD-approved TLS encryption
- **SV-230309**: Local RHEL 8 initialization files must not execute world-writable
- **SV-230331**: RHEL 8 temporary user accounts must be provisioned with an expiration
- **SV-230381**: RHEL 8 must display the date and time of the last successful account
- **SV-244526**: The RHEL 8 SSH daemon must be configured to use system-wide crypto policies.
- **SV-251714**: RHEL 8 systems below version 8.4 must ensure the password complexity module in the system-auth file is configured for three retries or less.
- **SV-251715**: RHEL 8 systems below version 8.4 must ensure the password complexity module in the password-auth file is configured for three retries or less.
- **SV-255924**: RHEL 8 SSH server must be configured to use only FIPS-validated key exchange algorithms.
