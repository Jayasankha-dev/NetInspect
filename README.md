# NetInspect Advanced Binary Analyzer

<img width="1920" height="1080" alt="Capture" src="https://github.com/user-attachments/assets/cbeb3b1d-317c-4382-9b51-521a81152af7" />


**Defensive Windows PE/static analysis and controlled runtime network triage.**

NetInspect Advanced is a Windows-focused analysis tool designed to help inspect PE executables and DLLs, review their metadata, examine imported dependencies, and perform **explicitly authorized runtime network observation**.

## Features

### Static PE Analysis

* PE32 / PE32+ detection
* Machine architecture identification
* Entry Point and Image Base
* Section table inspection
* Section sizes and entropy
* Import table analysis
* Export table analysis
* Imported DLL identification
* SHA-256 hashing
* File size and metadata
* Strings extraction
* Hexadecimal preview
* Basic heuristic indicators

**Static analysis does not execute the selected file.**

### Windows File Metadata

NetInspect can collect Windows metadata including:

* File version
* Product version
* Company name
* Product name
* File description
* Original filename
* Internal name
* Copyright information
* Creation and modification timestamps

### Authenticode Analysis

The tool can inspect Windows Authenticode information, including:

* Signature status
* Signature verification message
* Signer
* Certificate issuer
* Certificate thumbprint
* Certificate validity period

A valid digital signature is treated as evidence about publisher identity/integrity, **not as proof that a file is malware-free**.

### Imported DLL Analysis

When an executable imports DLLs, NetInspect can inspect the referenced dependencies and, where available, resolve them from the relevant Windows search locations.

The tool can display:

* DLL name
* Import information
* Resolved file path
* File size
* SHA-256
* Basic metadata

This allows dependencies to be selected and analyzed individually rather than requiring the user to manually locate them.

### Runtime Network Monitoring

Runtime monitoring is **opt-in**.

The selected executable is not automatically launched during static analysis. When the user explicitly chooses runtime analysis, NetInspect can observe the resulting process activity and correlate it with:

* Process ID
* Process name
* Parent process
* Process tree
* TCP connections
* UDP activity/snapshots
* Local endpoints
* Remote endpoints
* Connection state
* Observation timestamps

Runtime network results are intended for **triage and behavioral observation**, not as a guarantee that every possible network activity has been detected.

### Process Correlation

Multiple instances of the same executable may exist simultaneously.

NetInspect therefore correlates observations using process information rather than assuming that a process name uniquely identifies one instance.

This helps distinguish situations such as:

```text
Target
 └── Target.exe
      ├── PID 12004
      ├── PID 6800
      └── PID 4112
```

### Evidence & Export

Analysis results can be preserved for later review.

Exported evidence can include:

* File identification
* Hashes
* PE information
* Sections
* Entropy
* Imports
* Exports
* Strings
* Metadata
* Authenticode information
* Related files
* Process information
* Runtime network observations
* Timestamps
* Heuristic indicators

JSON export is suitable for machine-readable processing and further analysis.

HTML export provides a human-readable report.

## Workflow

A typical investigation can follow this workflow:

```text
Select File
    ↓
Calculate Hashes
    ↓
Parse PE Structure
    ↓
Analyze Sections
    ↓
Review Imports / Exports
    ↓
Resolve Related DLLs
    ↓
Inspect Strings
    ↓
Check Windows Metadata
    ↓
Check Authenticode
    ↓
Review Heuristic Indicators
    ↓
Optional Runtime Analysis
    ↓
Correlate Processes + Network
    ↓
Export Evidence
```

## Important Safety Design

NetInspect separates **static analysis** from **runtime execution**.

Selecting a file for analysis does **not** automatically execute it.

Runtime analysis requires an explicit user action through the Runtime Network functionality.

This design helps prevent accidental execution of an unknown executable during normal static inspection.

> **Important:** Runtime analysis should only be performed on software you are authorized to execute and monitor. For unknown or potentially malicious files, use an isolated analysis environment such as a disposable VM or sandbox.

## Heuristic Indicators

NetInspect may report suspicious characteristics discovered during analysis.

These indicators can help prioritize files for further investigation, but they are **not malware verdicts**.

For example:

```text
Indicator detected
        ↓
Further investigation
        ↓
Hash / signature / metadata
        ↓
Imports / strings / PE structure
        ↓
Runtime behavior
        ↓
Overall assessment
```

A suspicious indicator by itself does not establish maliciousness.

Likewise, the absence of suspicious indicators does not prove that a file is completely safe.

## Requirements

* Windows 10 or later
* Python environment for development
* PowerShell available for Windows metadata/signature checks
* Required Python dependencies listed by the project
* Administrator privileges may be required for some system-level observations

## Build

To build the standalone Windows executable:

```bat
build.bat
```

The resulting executable should be available at:

```text
dist\NetInspect-Advanced.exe
```

For development/testing, run the Python entry point directly according to the project structure.

## Recommended Analysis Practice

For an unknown file:

1. Record the SHA-256 hash.
2. Perform static PE analysis.
3. Review sections and entropy.
4. Examine imports and related DLLs.
5. Inspect strings.
6. Check version and publisher metadata.
7. Check Authenticode status.
8. Compare hashes against trusted sources where appropriate.
9. Only perform runtime analysis in an isolated environment when authorized.
10. Export the complete evidence set.

## Limitations

NetInspect is an **analysis and triage tool**, not a replacement for a full EDR, antivirus engine, malware sandbox, or professional reverse-engineering suite.

Network snapshots may miss short-lived connections, and static heuristics can produce both false positives and false negatives.

Results should therefore be interpreted together with other evidence.

## Project Philosophy

NetInspect is designed around three principles:

**Inspect before executing.**
Static analysis should not require launching the target.

**Execute only by explicit choice.**
Runtime monitoring is opt-in and separated from static inspection.

**Indicators are evidence, not verdicts.**
A responsible analysis combines multiple independent signals before reaching a conclusion.

---

### License

Add your project's chosen license here, for example:

```text
MIT License

Copyright (c) 2026 NetInspect

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files, to deal in the Software
without restriction, including without limitation the rights to use, copy,
modify, merge, publish, distribute, sublicense, and/or sell copies of the
Software.
```

**NetInspect Advanced Binary Analyzer**
*Defensive Security • PE Analysis • Forensics • Runtime Network Triage*
