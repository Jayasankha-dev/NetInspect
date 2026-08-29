import hashlib
import html
import json
import math
import os
import re
import struct
import subprocess
import threading
import time
import tkinter as tk

from tkinter import ttk, filedialog, messagebox


APP_NAME = "NetInspect Binary Analyzer"
APP_VERSION = "3.1.0"


# ============================================================
# BASIC FILE UTILITIES
# ============================================================

def entropy(data):
    if not data:
        return 0.0

    counts = [0] * 256

    for byte in data:
        counts[byte] += 1

    total = len(data)

    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts
        if count
    )


def file_hash(path, algorithm):
    digest = hashlib.new(algorithm)

    with open(path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def sha256_file(path):
    return file_hash(path, "sha256")


def md5_file(path):
    return file_hash(path, "md5")


def safe_read(data, offset, length):
    if (
        offset is None
        or offset < 0
        or length < 0
        or offset + length > len(data)
    ):
        return None

    return data[offset:offset + length]


def u16(data, offset):
    raw = safe_read(data, offset, 2)
    return struct.unpack("<H", raw)[0] if raw else None


def u32(data, offset):
    raw = safe_read(data, offset, 4)
    return struct.unpack("<I", raw)[0] if raw else None


def u64(data, offset):
    raw = safe_read(data, offset, 8)
    return struct.unpack("<Q", raw)[0] if raw else None


def cstr(data, offset, maximum=512):
    if offset is None or offset < 0 or offset >= len(data):
        return ""

    end = data.find(
        b"\0",
        offset,
        min(len(data), offset + maximum)
    )

    if end < 0:
        end = min(len(data), offset + maximum)

    return data[offset:end].decode("latin-1", "replace")


def ascii_strings(data, minimum=4):
    pattern = rb"[\x20-\x7e]{%d,}" % minimum
    return [
        match.decode("latin-1", "replace")
        for match in re.findall(pattern, data)
    ]


def unicode_strings(data, minimum=4):
    output = []

    pattern = rb"(?:[\x20-\x7e]\x00){%d,}" % minimum

    for match in re.findall(pattern, data):
        try:
            output.append(match.decode("utf-16le", "replace"))
        except Exception:
            pass

    return output


def rva_to_offset(sections, rva):
    for section in sections:
        va = section["virtual_address"]
        raw_size = section["raw_size"]

        if va <= rva < va + max(
            section["virtual_size"],
            raw_size
        ):
            delta = rva - va

            if delta < raw_size:
                return section["raw_pointer"] + delta

    return None


# ============================================================
# PE PARSER
# ============================================================

class PEParser:

    def __init__(self, data):
        self.data = data
        self.sections = []
        self.info = {}
        self.imports = []
        self.exports = []

        self.parse()

    def parse(self):
        data = self.data

        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError("Not a valid MZ/PE file.")

        pe_offset = u32(data, 0x3C)

        if (
            pe_offset is None
            or safe_read(data, pe_offset, 4) != b"PE\0\0"
        ):
            raise ValueError("Invalid PE signature.")

        coff = pe_offset + 4

        machine = u16(data, coff)
        section_count = u16(data, coff + 2)
        timestamp = u32(data, coff + 4)
        optional_header_size = u16(data, coff + 16)
        characteristics = u16(data, coff + 18)

        optional_header = coff + 20

        magic = u16(data, optional_header)

        is_64bit = magic == 0x20B

        if magic not in (0x10B, 0x20B):
            raise ValueError("Unsupported PE optional header.")

        entry_point = u32(data, optional_header + 16)

        image_base = (
            u64(data, optional_header + 24)
            if is_64bit
            else u32(data, optional_header + 28)
        )

        image_size = u32(data, optional_header + 56)
        subsystem = u16(data, optional_header + 68)
        dll_characteristics = u16(data, optional_header + 70)

        data_directory = optional_header + (
            112 if is_64bit else 96
        )

        export_rva = u32(data, data_directory) or 0
        import_rva = u32(data, data_directory + 8) or 0

        section_table = optional_header + optional_header_size

        for index in range(section_count):

            offset = section_table + index * 40

            raw = safe_read(data, offset, 40)

            if not raw:
                break

            name = (
                raw[:8]
                .split(b"\0", 1)[0]
                .decode("latin-1", "replace")
            )

            virtual_size = u32(raw, 8) or 0
            virtual_address = u32(raw, 12) or 0
            raw_size = u32(raw, 16) or 0
            raw_pointer = u32(raw, 20) or 0
            section_characteristics = u32(raw, 36) or 0

            blob = safe_read(
                data,
                raw_pointer,
                min(
                    raw_size,
                    max(0, len(data) - raw_pointer)
                )
            ) or b""

            self.sections.append(
                {
                    "name": name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "raw_pointer": raw_pointer,
                    "characteristics": section_characteristics,
                    "entropy": entropy(blob),
                }
            )

        self.info = {
            "Machine": {
                0x14C: "Intel 386 (I386)",
                0x8664: "x64",
                0x1C0: "ARM",
                0xAA64: "ARM64",
            }.get(machine, hex(machine)),

            "Architecture": "PE32+" if is_64bit else "PE32",

            "Sections": section_count,

            "Entry Point RVA": f"0x{entry_point:08X}",

            "Image Base": f"0x{image_base:X}",

            "Image Size": f"0x{image_size:X}",

            "Subsystem": {
                2: "Windows GUI",
                3: "Windows Console",
            }.get(subsystem, str(subsystem)),

            "Characteristics": f"0x{characteristics:04X}",

            "DLL Characteristics": (
                f"0x{dll_characteristics:04X}"
            ),

            "TimeDateStamp": timestamp,

            "Import RVA": f"0x{import_rva:08X}",

            "Export RVA": f"0x{export_rva:08X}",
        }

        if import_rva:
            self.parse_imports(import_rva, is_64bit)

        if export_rva:
            self.parse_exports(export_rva)

    def parse_imports(self, rva, is_64bit):

        offset = rva_to_offset(self.sections, rva)

        if offset is None:
            return

        step = 8 if is_64bit else 4

        for _ in range(512):

            descriptor = safe_read(
                self.data,
                offset,
                20
            )

            if not descriptor:
                break

            original_first_thunk = u32(
                descriptor, 0
            ) or 0

            name_rva = u32(
                descriptor, 12
            ) or 0

            first_thunk = u32(
                descriptor, 16
            ) or 0

            if not (
                original_first_thunk
                or name_rva
                or first_thunk
            ):
                break

            name_offset = rva_to_offset(
                self.sections,
                name_rva
            )

            dll_name = (
                cstr(self.data, name_offset)
                if name_offset is not None
                else "Unknown"
            )

            functions = []

            thunk_offset = rva_to_offset(
                self.sections,
                original_first_thunk or first_thunk
            )

            if thunk_offset is not None:

                for index in range(2048):

                    position = thunk_offset + index * step

                    value = (
                        u64(self.data, position)
                        if is_64bit
                        else u32(self.data, position)
                    )

                    if value is None or value == 0:
                        break

                    ordinal_flag = (
                        1 << 63
                        if is_64bit
                        else 1 << 31
                    )

                    if value & ordinal_flag:

                        functions.append(
                            f"Ordinal #{value & 0xFFFF}"
                        )

                    else:

                        import_offset = rva_to_offset(
                            self.sections,
                            int(value)
                        )

                        if import_offset is not None:
                            functions.append(
                                cstr(
                                    self.data,
                                    import_offset + 2
                                )
                            )
                        else:
                            functions.append("Unknown")

            self.imports.append(
                (dll_name, functions)
            )

            offset += 20

    def parse_exports(self, rva):

        offset = rva_to_offset(
            self.sections,
            rva
        )

        header = (
            safe_read(self.data, offset, 40)
            if offset is not None
            else None
        )

        if not header:
            return

        number_of_names = u32(
            header, 24
        ) or 0

        address_of_names_rva = u32(
            header, 32
        ) or 0

        names_offset = (
            rva_to_offset(
                self.sections,
                address_of_names_rva
            )
            if address_of_names_rva
            else None
        )

        if names_offset is None:
            return

        for index in range(
            min(number_of_names, 10000)
        ):

            name_rva = u32(
                self.data,
                names_offset + index * 4
            )

            if name_rva is not None:

                name_offset = rva_to_offset(
                    self.sections,
                    name_rva
                )

                if name_offset is not None:
                    self.exports.append(
                        cstr(self.data, name_offset)
                    )


# ============================================================
# HEURISTIC TRIAGE
# ============================================================

SUSPICIOUS_IMPORTS = {
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtWriteVirtualMemory",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenA",
    "InternetOpenW",
    "WinHttpOpen",
    "WinHttpConnect",
    "RegSetValueExA",
    "RegSetValueExW",
    "CreateServiceA",
    "CreateServiceW",
    "WSAStartup",
    "connect",
    "InternetConnectA",
    "HttpOpenRequestA",
}


class Analyzer:

    def __init__(self, path, data, pe):
        self.path = path
        self.data = data
        self.pe = pe

    def findings(self):

        findings = []

        if self.pe:

            high_entropy_sections = [
                section["name"]
                for section in self.pe.sections
                if section["entropy"] >= 7.2
            ]

            if high_entropy_sections:

                findings.append(
                    "High-entropy section(s): "
                    + ", ".join(high_entropy_sections)
                )

            imported_functions = {
                function
                for _, functions in self.pe.imports
                for function in functions
            }

            hits = sorted(
                imported_functions
                & SUSPICIOUS_IMPORTS
            )

            if hits:

                findings.append(
                    "Behavior-relevant imports: "
                    + ", ".join(hits)
                )

            section_names = {
                section["name"].lower()
                for section in self.pe.sections
            }

            packer_hints = {
                "UPX": [
                    b"UPX0",
                    b"UPX1",
                    b"UPX2",
                ],
                "ASPack": [
                    b".aspack",
                    b"ASPack",
                ],
                "Themida": [
                    b".themida",
                    b"Themida",
                ],
                "VMProtect": [
                    b".vmp",
                    b"VMProtect",
                ],
            }

            for packer, hints in packer_hints.items():

                if any(
                    hint.lower() in section_names
                    or hint in self.data
                    for hint in hints
                ):

                    findings.append(
                        "Packer/protector hint: "
                        + packer
                    )

        if b"X5O!P%@AP" in self.data:

            findings.append(
                "EICAR test signature found (test pattern)."
            )

        return findings or [
            "No built-in heuristic indicators triggered."
        ]


# ============================================================
# WINDOWS / POWERSHELL CHECKS
# ============================================================

def powershell_json(script, target_path=None, timeout=30):

    environment = os.environ.copy()

    if target_path:
        environment["NETINSPECT_TARGET"] = (
            os.path.abspath(target_path)
        )

    try:

        process = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=environment,
        )

    except Exception as exc:

        return {
            "error": str(exc)
        }

    if process.returncode != 0:

        return {
            "error": (
                process.stderr.strip()
                or "PowerShell command failed."
            )
        }

    output = process.stdout.strip()

    if not output:

        return {
            "error": "PowerShell returned no output."
        }

    try:

        return json.loads(output)

    except json.JSONDecodeError:

        return {
            "error": "PowerShell returned invalid JSON.",
            "raw_output": output,
        }


def version_info(path):

    script = r"""
$ErrorActionPreference = "Stop"

$path = $env:NETINSPECT_TARGET

if ([string]::IsNullOrWhiteSpace($path)) {
    throw "Target path was not provided."
}

if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "Target file does not exist: $path"
}

$item = Get-Item -LiteralPath $path -ErrorAction Stop
$version = $item.VersionInfo

[ordered]@{
    Name = $item.Name
    Length = $item.Length
    CreationTime = $item.CreationTime.ToString("o")
    LastWriteTime = $item.LastWriteTime.ToString("o")

    CompanyName = [string]$version.CompanyName
    ProductName = [string]$version.ProductName
    FileDescription = [string]$version.FileDescription
    FileVersion = [string]$version.FileVersion
    ProductVersion = [string]$version.ProductVersion
    OriginalFilename = [string]$version.OriginalFilename
    InternalName = [string]$version.InternalName
    LegalCopyright = [string]$version.LegalCopyright
} | ConvertTo-Json -Depth 5 -Compress
"""

    return powershell_json(
        script,
        target_path=path
    )


def signature(path):

    script = r"""
$ErrorActionPreference = "Stop"

$path = $env:NETINSPECT_TARGET

if ([string]::IsNullOrWhiteSpace($path)) {
    throw "Target path was not provided."
}

if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    throw "Target file does not exist: $path"
}

$sig = Get-AuthenticodeSignature `
    -LiteralPath $path `
    -ErrorAction Stop

$result = [ordered]@{
    Status = [string]$sig.Status
    StatusMessage = [string]$sig.StatusMessage

    Signer = if ($sig.SignerCertificate) {
        [string]$sig.SignerCertificate.Subject
    } else {
        $null
    }

    Issuer = if ($sig.SignerCertificate) {
        [string]$sig.SignerCertificate.Issuer
    } else {
        $null
    }

    Thumbprint = if ($sig.SignerCertificate) {
        [string]$sig.SignerCertificate.Thumbprint
    } else {
        $null
    }

    NotBefore = if ($sig.SignerCertificate) {
        $sig.SignerCertificate.NotBefore.ToString("o")
    } else {
        $null
    }

    NotAfter = if ($sig.SignerCertificate) {
        $sig.SignerCertificate.NotAfter.ToString("o")
    } else {
        $null
    }

    Subject = if ($sig.SignerCertificate) {
        [string]$sig.SignerCertificate.Subject
    } else {
        $null
    }
}

$result | ConvertTo-Json -Depth 5 -Compress
"""

    return powershell_json(
        script,
        target_path=path
    )


# ============================================================
# PROCESS / NETWORK
# ============================================================

def get_process_snapshot():

    result = {}

    script = r"""
Get-CimInstance Win32_Process |
Select-Object ProcessId,ParentProcessId,Name,ExecutablePath |
ConvertTo-Json -Compress
"""

    try:

        raw = subprocess.check_output(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
        )

        parsed = json.loads(raw)

        if not isinstance(parsed, list):
            parsed = [parsed]

        for item in parsed:

            pid = int(item["ProcessId"])

            parent = int(
                item.get("ParentProcessId") or 0
            )

            result[pid] = {
                "name": item.get("Name") or "",
                "parent_pid": parent,
                "path": item.get("ExecutablePath") or "",
            }

    except Exception:
        pass

    return result


def get_descendants(root_pid, snapshot):

    process_ids = {root_pid}

    changed = True

    while changed:

        changed = False

        for pid, process in snapshot.items():

            if (
                process["parent_pid"] in process_ids
                and pid not in process_ids
            ):

                process_ids.add(pid)
                changed = True

    return process_ids


def net_connections():

    try:

        import psutil

    except ImportError:

        return []

    output = []

    try:

        connections = psutil.net_connections(
            kind="inet"
        )

    except Exception:

        return []

    for connection in connections:

        local = "-"

        remote = "-"

        if connection.laddr:
            local = (
                f"{connection.laddr.ip}:"
                f"{connection.laddr.port}"
            )

        if connection.raddr:
            remote = (
                f"{connection.raddr.ip}:"
                f"{connection.raddr.port}"
            )

        process_name = "-"

        if connection.pid:

            try:

                process_name = psutil.Process(
                    connection.pid
                ).name()

            except Exception:
                pass

        output.append(
            (
                connection.pid or 0,
                process_name,
                local,
                remote,
                connection.status,
            )
        )

    return output


def find_running_instances(executable_name):

    script = f"""
Get-CimInstance Win32_Process |
Where-Object {{ $_.Name -ieq '{executable_name.replace("'", "''")}' }} |
Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine |
ConvertTo-Json -Depth 5 -Compress
"""

    try:

        raw = subprocess.check_output(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ],
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
        )

        if not raw.strip():
            return []

        parsed = json.loads(raw)

        if not isinstance(parsed, list):
            parsed = [parsed]

        return parsed

    except Exception as exc:

        return [
            {
                "error": str(exc)
            }
        ]


# ============================================================
# APPLICATION
# ============================================================

class App(tk.Tk):

    def __init__(self):

        super().__init__()

        self.title(
            f"{APP_NAME} | {APP_VERSION}"
        )

        self.geometry("1400x900")
        self.minsize(1150, 720)

        self.configure(
            bg="#151515"
        )

        self.path = None
        self.data = b""
        self.pe = None

        self.monitoring = False
        self.runtime = None
        self.runtime_root_pid = None
        self.runtime_rows = []
        self.runtime_lock = threading.Lock()

        self.checks = {}

        self.build()


    # ========================================================
    # STYLE
    # ========================================================

    def style(self):

        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "TNotebook",
            background="#151515",
            borderwidth=0,
        )

        style.configure(
            "TNotebook.Tab",
            background="#303030",
            foreground="#DDDDDD",
            padding=(13, 7),
        )

        style.map(
            "TNotebook.Tab",
            background=[
                ("selected", "#168BD1")
            ],
        )

        style.configure(
            "Treeview",
            background="#202020",
            foreground="#DDDDDD",
            fieldbackground="#202020",
            rowheight=25,
        )

        style.configure(
            "Treeview.Heading",
            background="#303030",
            foreground="#00E6C3",
        )


    # ========================================================
    # UI
    # ========================================================

    def build(self):

        self.style()

        top = tk.Frame(
            self,
            bg="#151515"
        )

        top.pack(
            fill="x",
            padx=14,
            pady=10
        )

        tk.Label(
            top,
            text="◈",
            fg="#F2B544",
            bg="#151515",
            font=("Segoe UI", 22, "bold"),
        ).pack(side="left")

        tk.Label(
            top,
            text=APP_NAME,
            fg="#F0F0F0",
            bg="#151515",
            font=("Segoe UI", 18, "bold"),
        ).pack(
            side="left",
            padx=8
        )

        tk.Label(
            top,
            text="Static Analysis + User-Controlled Runtime Triage",
            fg="#888888",
            bg="#151515",
        ).pack(
            side="left",
            pady=7
        )

        ttk.Button(
            top,
            text="Full Export",
            command=self.export,
        ).pack(
            side="right",
            padx=4
        )

        ttk.Button(
            top,
            text="Clear",
            command=self.clear,
        ).pack(
            side="right",
            padx=4
        )

        ttk.Button(
            top,
            text="Open File",
            command=self.open_file,
        ).pack(
            side="right",
            padx=4
        )

        self.path_var = tk.StringVar(
            value="No file selected"
        )

        tk.Label(
            self,
            textvariable=self.path_var,
            anchor="w",
            fg="#00E6C3",
            bg="#1C1C1C",
            padx=10,
            pady=7,
        ).pack(
            fill="x",
            padx=14
        )

        self.nb = ttk.Notebook(self)

        self.nb.pack(
            fill="both",
            expand=True,
            padx=14,
            pady=12
        )

        tab_names = [
            "File Info",
            "PE",
            "Sections",
            "Imports",
            "DLL Analyze",
            "Strings",
            "Hex",
            "Entropy",
            "Heuristics",
            "System Checks",
            "Runtime Network",
        ]

        self.tabs = {}

        for name in tab_names:

            frame = tk.Frame(
                self.nb,
                bg="#171717"
            )

            self.tabs[name] = frame

            self.nb.add(
                frame,
                text=name
            )

        self.info = self.text(
            self.tabs["File Info"]
        )

        self.pebox = self.text(
            self.tabs["PE"]
        )

        self.strbox = self.text(
            self.tabs["Strings"]
        )

        self.hexbox = self.text(
            self.tabs["Hex"]
        )

        self.heurbox = self.text(
            self.tabs["Heuristics"]
        )

        self.sectree = self.tree(
            self.tabs["Sections"],
            (
                "Name",
                "VA",
                "Raw Size",
                "Raw Offset",
                "Characteristics",
                "Entropy",
            ),
        )

        self.imptree = self.tree(
            self.tabs["Imports"],
            (
                "DLL",
                "Imported Functions",
            ),
        )

        self.enttree = self.tree(
            self.tabs["Entropy"],
            (
                "Section",
                "Size",
                "Entropy",
                "Assessment",
            ),
        )

        self.build_dll()
        self.build_checks()
        self.build_runtime()

        self.status = tk.StringVar(
            value="Ready"
        )

        tk.Label(
            self,
            textvariable=self.status,
            fg="#999999",
            bg="#151515",
            anchor="w",
        ).pack(
            fill="x",
            padx=14,
            pady=(0, 8)
        )


    def text(self, parent):

        frame = tk.Frame(
            parent,
            bg="#171717"
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=8,
            pady=8
        )

        box = tk.Text(
            frame,
            bg="#111111",
            fg="#DDDDDD",
            insertbackground="white",
            font=("Consolas", 10),
            wrap="none",
            relief="flat",
        )

        vertical = ttk.Scrollbar(
            frame,
            command=box.yview
        )

        horizontal = ttk.Scrollbar(
            frame,
            orient="horizontal",
            command=box.xview
        )

        box.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set,
        )

        box.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        vertical.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        horizontal.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        frame.rowconfigure(
            0,
            weight=1
        )

        frame.columnconfigure(
            0,
            weight=1
        )

        return box


    def tree(self, parent, columns):

        frame = tk.Frame(
            parent,
            bg="#171717"
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=8,
            pady=8
        )

        tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
        )

        for column in columns:

            tree.heading(
                column,
                text=column
            )

            tree.column(
                column,
                width=190,
                anchor="w"
            )

        vertical = ttk.Scrollbar(
            frame,
            command=tree.yview
        )

        horizontal = ttk.Scrollbar(
            frame,
            orient="horizontal",
            command=tree.xview
        )

        tree.configure(
            yscrollcommand=vertical.set,
            xscrollcommand=horizontal.set,
        )

        tree.grid(
            row=0,
            column=0,
            sticky="nsew"
        )

        vertical.grid(
            row=0,
            column=1,
            sticky="ns"
        )

        horizontal.grid(
            row=1,
            column=0,
            sticky="ew"
        )

        frame.rowconfigure(
            0,
            weight=1
        )

        frame.columnconfigure(
            0,
            weight=1
        )

        return tree


    # ========================================================
    # DLL ANALYSIS
    # ========================================================

    def build_dll(self):

        tab = self.tabs["DLL Analyze"]

        bar = tk.Frame(
            tab,
            bg="#171717"
        )

        bar.pack(
            fill="x",
            padx=8,
            pady=8
        )

        self.dllvar = tk.StringVar(
            value="Select an imported DLL"
        )

        self.dllcombo = ttk.Combobox(
            bar,
            textvariable=self.dllvar,
            state="readonly",
            width=60,
        )

        self.dllcombo.pack(
            side="left"
        )

        ttk.Button(
            bar,
            text="Analyze Selected DLL",
            command=self.analyze_dll,
        ).pack(
            side="left",
            padx=6
        )

        ttk.Button(
            bar,
            text="Open DLL Manually",
            command=self.open_dll,
        ).pack(
            side="left"
        )

        self.dllbox = self.text(tab)


    # ========================================================
    # SYSTEM CHECKS
    # ========================================================

    def build_checks(self):

        tab = self.tabs["System Checks"]

        bar = tk.Frame(
            tab,
            bg="#171717"
        )

        bar.pack(
            fill="x",
            padx=8,
            pady=8
        )

        ttk.Button(
            bar,
            text="Run All Checks",
            command=self.run_checks,
        ).pack(
            side="left"
        )

        self.checkbox = self.text(tab)


    # ========================================================
    # RUNTIME NETWORK
    # ========================================================

    def build_runtime(self):

        tab = self.tabs["Runtime Network"]

        bar = tk.Frame(
            tab,
            bg="#171717"
        )

        bar.pack(
            fill="x",
            padx=8,
            pady=8
        )

        ttk.Button(
            bar,
            text="▶ Run & Monitor",
            command=self.start_runtime,
        ).pack(
            side="left"
        )

        ttk.Button(
            bar,
            text="■ Stop Monitoring",
            command=self.stop_runtime,
        ).pack(
            side="left",
            padx=5
        )

        ttk.Button(
            bar,
            text="Terminate Target",
            command=self.terminate_runtime,
        ).pack(
            side="left"
        )

        tk.Label(
            bar,
            text="Duration:",
            bg="#171717",
            fg="#BBBBBB",
        ).pack(
            side="left",
            padx=(20, 4)
        )

        self.duration = tk.StringVar(
            value="60"
        )

        ttk.Combobox(
            bar,
            textvariable=self.duration,
            values=[
                "30",
                "60",
                "120",
                "300",
            ],
            width=7,
            state="readonly",
        ).pack(
            side="left"
        )

        self.rtstatus = tk.StringVar(
            value=(
                "Idle — target will NOT run "
                "until you click Run & Monitor"
            )
        )

        tk.Label(
            tab,
            textvariable=self.rtstatus,
            fg="#00E6C3",
            bg="#171717",
            anchor="w",
        ).pack(
            fill="x",
            padx=10
        )

        self.rttree = self.tree(
            tab,
            (
                "Time",
                "PID",
                "Process",
                "Local",
                "Remote",
                "Status",
            ),
        )


    # ========================================================
    # GENERAL HELPERS
    # ========================================================

    def settext(self, widget, text):

        widget.delete(
            "1.0",
            "end"
        )

        widget.insert(
            "1.0",
            text
        )


    # ========================================================
    # FILE OPEN / ANALYSIS
    # ========================================================

    def open_file(self):

        path = filedialog.askopenfilename(
            filetypes=[
                (
                    "Executable / Binary",
                    "*.exe *.dll *.sys *.ocx *.scr *.com *.bin",
                ),
                (
                    "All files",
                    "*.*"
                ),
            ]
        )

        if path:
            self.analyze(path)


    def open_dll(self):

        path = filedialog.askopenfilename(
            filetypes=[
                (
                    "DLL",
                    "*.dll"
                ),
                (
                    "All files",
                    "*.*"
                ),
            ]
        )

        if path:
            self.analyze_dll_path(path)


    def analyze(self, path):

        try:

            with open(path, "rb") as file:
                data = file.read()

            self.path = path
            self.data = data

            self.pe = (
                PEParser(data)
                if data[:2] == b"MZ"
                else None
            )

            self.populate()

            self.status.set(
                f"Analyzed {os.path.basename(path)} "
                f"| {len(data):,} bytes"
            )

        except Exception as exc:

            messagebox.showerror(
                "Analysis Error",
                str(exc)
            )


    def clear(self):

        self.stop_runtime()

        self.path = None
        self.data = b""
        self.pe = None
        self.checks = {}

        self.path_var.set(
            "No file selected"
        )

        self.dllvar.set(
            "Select an imported DLL"
        )

        self.dllcombo["values"] = []

        for widget in [
            self.info,
            self.pebox,
            self.strbox,
            self.hexbox,
            self.heurbox,
            self.dllbox,
            self.checkbox,
        ]:

            self.settext(
                widget,
                ""
            )

        for tree in [
            self.sectree,
            self.imptree,
            self.enttree,
            self.rttree,
        ]:

            for item in tree.get_children():
                tree.delete(item)

        self.status.set(
            "Ready"
        )


    # ========================================================
    # POPULATE STATIC ANALYSIS
    # ========================================================

    def populate(self):

        self.path_var.set(
            self.path
        )

        size = len(self.data)

        file_type = (
            "PE executable"
            if self.pe
            else "Unknown / non-PE"
        )

        self.settext(
            self.info,
            "\n".join(
                [
                    f"File name       : {os.path.basename(self.path)}",
                    f"Full path       : {self.path}",
                    (
                        f"File size       : "
                        f"{size:,} bytes "
                        f"({size / 1024 / 1024:.2f} MiB)"
                    ),
                    f"MD5             : {md5_file(self.path)}",
                    f"SHA-256         : {sha256_file(self.path)}",
                    f"Overall entropy : {entropy(self.data):.4f}",
                    f"File type       : {file_type}",
                ]
            )
        )

        if self.pe:

            self.settext(
                self.pebox,
                "\n".join(
                    f"{key:20}: {value}"
                    for key, value
                    in self.pe.info.items()
                )
            )

            for tree in [
                self.sectree,
                self.imptree,
                self.enttree,
            ]:

                for item in tree.get_children():
                    tree.delete(item)

            for section in self.pe.sections:

                self.sectree.insert(
                    "",
                    "end",
                    values=(
                        section["name"],
                        (
                            f"0x"
                            f"{section['virtual_address']:08X}"
                        ),
                        section["raw_size"],
                        (
                            f"0x"
                            f"{section['raw_pointer']:08X}"
                        ),
                        (
                            f"0x"
                            f"{section['characteristics']:08X}"
                        ),
                        (
                            f"{section['entropy']:.3f}"
                        ),
                    )
                )

                assessment = (
                    "Likely packed/compressed"
                    if section["entropy"] >= 7.2
                    else (
                        "High entropy"
                        if section["entropy"] >= 6.8
                        else "Normal"
                    )
                )

                self.enttree.insert(
                    "",
                    "end",
                    values=(
                        section["name"],
                        section["raw_size"],
                        f"{section['entropy']:.3f}",
                        assessment,
                    )
                )

            for dll, functions in self.pe.imports:

                self.imptree.insert(
                    "",
                    "end",
                    values=(
                        dll,
                        ", ".join(functions[:250])
                        + (
                            " ..."
                            if len(functions) > 250
                            else ""
                        ),
                    )
                )

            dll_names = [
                dll
                for dll, _ in self.pe.imports
            ]

            self.dllcombo["values"] = dll_names

            if dll_names:
                self.dllcombo.current(0)

        strings = list(
            dict.fromkeys(
                ascii_strings(self.data)
                + unicode_strings(self.data)
            )
        )

        self.settext(
            self.strbox,
            "\n".join(
                strings[:30000]
            )
        )

        hex_lines = []

        for offset in range(
            0,
            min(len(self.data), 16384),
            16
        ):

            chunk = self.data[
                offset:offset + 16
            ]

            hex_text = " ".join(
                f"{byte:02X}"
                for byte in chunk
            )

            printable = "".join(
                chr(byte)
                if 32 <= byte < 127
                else "."
                for byte in chunk
            )

            hex_lines.append(
                f"{offset:08X}  "
                f"{hex_text:<47}  "
                f"{printable}"
            )

        self.settext(
            self.hexbox,
            "\n".join(hex_lines)
        )

        findings = Analyzer(
            self.path,
            self.data,
            self.pe
        ).findings()

        self.settext(
            self.heurbox,
            "HEURISTIC TRIAGE\n"
            "================\n\n"
            + "\n".join(
                "• " + finding
                for finding in findings
            )
            + "\n\n"
            "Note: Heuristic indicators are not proof of malware."
        )


    # ========================================================
    # DLL RESOLUTION
    # ========================================================

    def resolve_dll(self, name):

        candidates = [
            os.path.join(
                os.path.dirname(self.path),
                name
            ),

            os.path.join(
                os.environ.get(
                    "WINDIR",
                    r"C:\Windows"
                ),
                "System32",
                name
            ),

            os.path.join(
                os.environ.get(
                    "WINDIR",
                    r"C:\Windows"
                ),
                "SysWOW64",
                name
            ),
        ]

        return next(
            (
                path
                for path in candidates
                if os.path.isfile(path)
            ),
            None
        )


    def analyze_dll(self):

        name = self.dllvar.get()

        path = (
            self.resolve_dll(name)
            if name
            else None
        )

        if path:

            self.analyze_dll_path(
                path
            )

        else:

            messagebox.showinfo(
                "DLL Not Found",
                (
                    f"Could not locate "
                    f"{name or 'the selected DLL'} "
                    "automatically.\n\n"
                    "Use Open DLL Manually."
                )
            )


    def analyze_dll_path(self, path):

        try:

            with open(path, "rb") as file:
                data = file.read()

            pe = (
                PEParser(data)
                if data[:2] == b"MZ"
                else None
            )

            lines = [
                f"Selected DLL : {os.path.basename(path)}",
                f"Path         : {path}",
                f"Size         : {len(data):,}",
                f"MD5          : {md5_file(path)}",
                f"SHA-256      : {sha256_file(path)}",
                f"Entropy      : {entropy(data):.4f}",
                (
                    f"PE           : "
                    f"{'Yes' if pe else 'No'}"
                ),
                "",
            ]

            if pe:

                lines += [
                    "PE METADATA"
                ]

                lines += [
                    f"{key:20}: {value}"
                    for key, value
                    in pe.info.items()
                ]

                lines += [
                    "",
                    "IMPORTS",
                ]

                for dll, functions in pe.imports:

                    lines.append(
                        f"{dll}: "
                        f"{', '.join(functions[:120])}"
                    )

            dll_version = version_info(path)
            dll_signature = signature(path)

            lines += [
                "",
                "VERSION / FILE METADATA",
                json.dumps(
                    dll_version,
                    indent=2,
                    default=str
                ),
                "",
                "AUTHENTICODE SIGNATURE",
                json.dumps(
                    dll_signature,
                    indent=2,
                    default=str
                ),
            ]

            self.settext(
                self.dllbox,
                "\n".join(lines)
            )

            self.nb.select(
                self.tabs["DLL Analyze"]
            )

        except Exception as exc:

            messagebox.showerror(
                "DLL Analysis Error",
                str(exc)
            )


    # ========================================================
    # AUTOMATED SYSTEM CHECKS
    # ========================================================

    def run_checks(self):

        if not self.path:

            messagebox.showinfo(
                "No File",
                "Select a file first."
            )

            return

        self.status.set(
            "Running Windows checks..."
        )

        threading.Thread(
            target=self._run_checks_worker,
            daemon=True
        ).start()


    def _run_checks_worker(self):

        try:

            version = version_info(
                self.path
            )

            auth_signature = signature(
                self.path
            )

            folder = os.path.dirname(
                self.path
            )

            inventory = []

            extensions = {
                ".exe",
                ".dll",
                ".sys",
                ".asi",
                ".ocx",
                ".scr",
            }

            for filename in sorted(
                os.listdir(folder)
            ):

                file_path = os.path.join(
                    folder,
                    filename
                )

                if (
                    os.path.isfile(file_path)
                    and os.path.splitext(
                        filename
                    )[1].lower()
                    in extensions
                ):

                    try:

                        inventory.append(
                            {
                                "name": filename,
                                "size": os.path.getsize(
                                    file_path
                                ),
                                "sha256": sha256_file(
                                    file_path
                                ),
                            }
                        )

                    except Exception:
                        pass

            running = find_running_instances(
                os.path.basename(self.path)
            )

            self.checks = {
                "version": version,
                "signature": auth_signature,
                "processes": running,
                "inventory": inventory,
            }

            lines = [
                "AUTOMATED WINDOWS CHECKS",
                "========================",
                "",
                f"Target: {self.path}",
                "",
                "[File Hashes]",
                f"MD5     : {md5_file(self.path)}",
                f"SHA-256 : {sha256_file(self.path)}",
                "",
                "[Version / File Metadata]",
                json.dumps(
                    version,
                    indent=2,
                    default=str
                ),
                "",
                "[Authenticode Signature]",
                json.dumps(
                    auth_signature,
                    indent=2,
                    default=str
                ),
                "",
                "[Currently Running Instances]",
            ]

            if running:

                lines.append(
                    json.dumps(
                        running,
                        indent=2,
                        default=str
                    )
                )

            else:

                lines.append(
                    "None"
                )

            lines += [
                "",
                "[Related EXE / DLL / SYS / ASI Inventory]",
            ]

            for item in inventory:

                lines.append(
                    (
                        f"{item['name']} | "
                        f"{item['size']:,} bytes | "
                        f"SHA256 {item['sha256']}"
                    )
                )

            report_text = "\n".join(
                lines
            )

            self.after(
                0,
                lambda: self._finish_checks(
                    report_text
                )
            )

        except Exception as exc:

            self.after(
                0,
                lambda: messagebox.showerror(
                    "System Check Error",
                    str(exc)
                )
            )


    def _finish_checks(self, text):

        self.settext(
            self.checkbox,
            text
        )

        self.nb.select(
            self.tabs["System Checks"]
        )

        self.status.set(
            "Windows checks completed."
        )


    # ========================================================
    # RUNTIME MONITORING
    # ========================================================

    def start_runtime(self):

        if self.monitoring:
            return

        if not self.path:

            messagebox.showinfo(
                "No File",
                "Select an EXE first."
            )

            return

        if (
            os.path.splitext(
                self.path
            )[1].lower()
            != ".exe"
        ):

            messagebox.showinfo(
                "Runtime",
                "Run & Monitor is available for EXE targets."
            )

            return

        try:

            duration = int(
                self.duration.get()
            )

        except ValueError:

            duration = 60

        try:

            # User-controlled execution.
            # The selected executable is NOT started automatically
            # during static analysis.
            self.runtime = subprocess.Popen(
                [self.path],
                cwd=os.path.dirname(self.path),
                creationflags=getattr(
                    subprocess,
                    "CREATE_NEW_PROCESS_GROUP",
                    0
                ),
            )

        except Exception as exc:

            messagebox.showerror(
                "Launch Failed",
                str(exc)
            )

            return

        self.runtime_root_pid = (
            self.runtime.pid
        )

        self.monitoring = True
        self.runtime_rows = []

        self.runtime_end = (
            time.time() + duration
        )

        for item in self.rttree.get_children():
            self.rttree.delete(item)

        self.rtstatus.set(
            f"Monitoring PID "
            f"{self.runtime_root_pid} "
            "and descendants..."
        )

        threading.Thread(
            target=self.monitor_loop,
            daemon=True
        ).start()


    def monitor_loop(self):

        root_pid = self.runtime_root_pid

        while (
            self.monitoring
            and time.time() < self.runtime_end
        ):

            snapshot = get_process_snapshot()

            process_ids = get_descendants(
                root_pid,
                snapshot
            )

            current_time = time.strftime(
                "%H:%M:%S"
            )

            connections = net_connections()

            rows = [
                (
                    current_time,
                    pid,
                    process_name,
                    local,
                    remote,
                    status,
                )
                for (
                    pid,
                    process_name,
                    local,
                    remote,
                    status,
                ) in connections
                if pid in process_ids
            ]

            with self.runtime_lock:

                self.runtime_rows.extend(
                    rows
                )

            self.after(
                0,
                self.refresh_runtime
            )

            remaining = max(
                0,
                int(
                    self.runtime_end
                    - time.time()
                )
            )

            process_count = len(
                process_ids
            )

            self.after(
                0,
                lambda remaining=remaining,
                count=process_count:
                self.rtstatus.set(
                    f"Monitoring {count} related "
                    f"process(es) | "
                    f"remaining {remaining}s"
                )
            )

            time.sleep(1)

        self.monitoring = False

        self.after(
            0,
            lambda: self.rtstatus.set(
                "Analysis complete — "
                f"{len(self.runtime_rows)} "
                "network observations recorded."
            )
        )


    def refresh_runtime(self):

        for item in self.rttree.get_children():
            self.rttree.delete(item)

        for row in self.runtime_rows[-500:]:

            self.rttree.insert(
                "",
                "end",
                values=row
            )


    def stop_runtime(self):

        self.monitoring = False

        if hasattr(
            self,
            "rtstatus"
        ):

            self.rtstatus.set(
                "Monitoring stopped by user."
            )


    def terminate_runtime(self):

        terminated = False

        if (
            self.runtime
            and self.runtime.poll() is None
        ):

            try:

                self.runtime.terminate()

                terminated = True

            except Exception:
                pass

        self.monitoring = False

        if terminated:

            self.rtstatus.set(
                "Target process termination requested."
            )

        else:

            self.rtstatus.set(
                "Target process is not currently running."
            )


    # ========================================================
    # EXPORT
    # ========================================================

    def export(self):

        if not self.path:

            messagebox.showinfo(
                "Export",
                "Select and analyze a file first."
            )

            return

        base = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                (
                    "JSON report",
                    "*.json"
                ),
                (
                    "HTML report",
                    "*.html"
                ),
                (
                    "Text report",
                    "*.txt"
                ),
            ],
            initialfile=(
                os.path.splitext(
                    os.path.basename(
                        self.path
                    )
                )[0]
                + "_NetInspect_Report"
            ),
        )

        if not base:
            return

        with self.runtime_lock:

            runtime_observations = list(
                self.runtime_rows
            )

        report = {
            "application": {
                "name": APP_NAME,
                "version": APP_VERSION,
            },

            "target": self.path,

            "generated_at": (
                time.strftime(
                    "%Y-%m-%dT%H:%M:%S"
                )
            ),

            "file": {
                "name": os.path.basename(
                    self.path
                ),
                "path": self.path,
                "size": len(self.data),
                "md5": md5_file(
                    self.path
                ),
                "sha256": sha256_file(
                    self.path
                ),
                "entropy": entropy(
                    self.data
                ),
            },

            "pe": (
                self.pe.info
                if self.pe
                else None
            ),

            "sections": (
                self.pe.sections
                if self.pe
                else []
            ),

            "imports": (
                [
                    {
                        "DLL": dll,
                        "Imported Functions": functions,
                    }
                    for dll, functions
                    in self.pe.imports
                ]
                if self.pe
                else []
            ),

            "exports": (
                self.pe.exports
                if self.pe
                else []
            ),

            "heuristics": (
                Analyzer(
                    self.path,
                    self.data,
                    self.pe
                ).findings()
                if self.pe
                else []
            ),

            "system_checks": self.checks,

            "runtime_network": {
                "observations": runtime_observations,
                "note": (
                    "No observation does not prove "
                    "absence of network capability."
                ),
            },
        }

        try:

            payload = json.dumps(
                report,
                indent=2,
                default=str
            )

            if base.lower().endswith(
                ".html"
            ):

                payload = (
                    "<html>"
                    "<head>"
                    "<meta charset='utf-8'>"
                    "<title>NetInspect Report</title>"
                    "</head>"
                    "<body style='"
                    "background:#111;"
                    "color:#ddd;"
                    "font-family:Consolas;"
                    "'>"
                    "<h1>NetInspect Binary Analyzer</h1>"
                    "<pre>"
                    + html.escape(payload)
                    + "</pre>"
                    "</body>"
                    "</html>"
                )

            with open(
                base,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(
                    payload
                )

            messagebox.showinfo(
                "Export Complete",
                base
            )

        except Exception as exc:

            messagebox.showerror(
                "Export Failed",
                str(exc)
            )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        import psutil

    except ImportError:

        root = tk.Tk()
        root.withdraw()

        messagebox.showwarning(
            "Dependency Missing",
            (
                "psutil is required.\n\n"
                "Install it with:\n"
                "py -m pip install psutil"
            )
        )

        root.destroy()

        raise SystemExit(1)

    app = App()

    app.mainloop()