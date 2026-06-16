# ------- Anti-Cheat (Valkyrie) — Complete Reverse Engineering Analysis

> **Project Name:** Valkyrie
> **Kernel Driver:** Randgrid.sys (Norse valkyrie — PDB: `Randgrid.pdb`)
> **Type:** Windows Kernel-Mode Driver (`.sys`)
> **Single Export:** `DriverEntry` @ `0x140C3C000`
> **Analysis Date:** 2026-04-14
> **Tool:** IDA Pro 9 

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Binary Overview](#2-binary-overview)
3. [Obfuscation & Anti-Analysis](#3-obfuscation--anti-analysis)
4. [Import Analysis](#4-import-analysis)
5. [Driver Initialization Flow](#5-driver-initialization-flow)
6. [Detection Vectors](#6-detection-vectors)
7. [Cryptography & Signature Verification](#7-cryptography--signature-verification)
8. [Telemetry & ETW Infrastructure](#8-telemetry--etw-infrastructure)
9. [Anti-Debug Mechanisms](#9-anti-debug-mechanisms)
10. [Advanced Techniques](#10-advanced-techniques)
11. [Function Map & Renames](#11-function-map--renames)
12. [AI / Machine Learning Indicators](#12-ai--machine-learning-indicators)
13. [Conclusions & Attack Surface](#13-conclusions--attack-surface)

---

## 1. Executive Summary

Ricochet is Activision's anti-cheat for Call of Duty. Its kernel driver is named **Randgrid** (part of the **Valkyrie** project). It operates as a Windows kernel driver with a single export (`DriverEntry`) and imports **688 functions** across 4 modules (`ntoskrnl`, `HAL`, `ci`, `cng`).

**Key findings:**

- **5-layer obfuscation**: String encryption, import obfuscation, Mixed Boolean Arithmetic (MBA), Control Flow Flattening (CFF), and a **custom VM interpreter with 329 opcodes** (Themida/VMProtect-level). Most functions resist Hex-Rays decompilation.
- **688 imports** — one of the largest import surfaces seen in an anti-cheat driver, with 672 from ntoskrnl alone.
- **20 detection vectors** identified: process monitoring, handle filtering, image load tracking, memory scanning, code integrity validation, driver enumeration, direct page table walking, TPM hardware attestation, and more.
- **No direct network stack** — zero WFP/TDI/WSK imports. All comms go through user-mode.
- **Heavy telemetry** via ETW (9 imports) and WMI (22+ imports) — data feeds server-side ML models.
- **Advanced capabilities**: UEFI variable access, hardware performance counters, IPI broadcast, direct CR3/INVLPG page table walking, TPM attestation ("ActivisionAIK"), and a massive 53-import KTM surface.
- **Dynamic API resolution** via `MmGetSystemRoutineAddress` — actual API surface is larger than visible imports.

---

## 2. Binary Overview

### Sections

| Section | Purpose |
|---------|---------|
| `.text` / `.text$mn` / `.text$mn$00` / `.text$mn$21` / `.text$s` | Code sections (split into subsections — likely LTO/PGO artifacts) |
| `.rdata` / `.rdata$zzzdbg` | Read-only data, debug info |
| `.data` | Writable globals |
| `.pdata` | Exception handling data |
| `.xdata` | Unwind information |
| `.idata$2-6` | Import directory tables |
| `.rsrc$01-02` | Resources |
| `.00cfg` | Control Flow Guard metadata |
| `.gfids` | Guard function ID table |

### Security Features

- **Control Flow Guard (CFG)**: `.00cfg` + `.gfids` sections present. `j___guard_dispatch_icall_fptr` function exists for indirect call validation.
- **Stack Cookies (GS)**: `j_j___report_gsfailure` handler present.
- **Structured Exception Handling**: `__C_specific_handler` imported.
- **Stack Probes**: `__chkstk` imported.

### Function Statistics

- **~1000+ functions** total in the binary
- **~68 nullsub functions** (empty stubs — likely stripped code paths or disabled features)
- **Largest function**: `LargeRoutine_70KB_MainLogicHub` @ `0x140A5BB74` — **70,696 bytes** (extremely large for a single function, indicates heavy CFF)
- **6 functions > 10KB**: suggests core detection/scan logic with obfuscation inflation

### Key Named Functions

| Address | Name | Size | Notes |
|---------|------|------|-------|
| `0x140C3C000` | `DriverEntry` | 5 | Thunk → `DriverEntry_0` |
| `0x14045243C` | `DriverEntry_0` | 357 | Real entry — obfuscated init with relocation fixups |
| `0x140A29650` | `NotifyRoutine` | 5 | Thunk → `ProcessNotifyCallback_Real` |
| `0x140A59438` | `ProcessNotifyCallback_Real` | 169 | Process creation notification handler |
| `0x140C46DF7` | `RandgridInit_CallbackRegistration` | — | Main initialization — registers callbacks, queries system info |
| `0x140A210B2` | `CoreScanEngine_MmCopyMemory` | 16,933 | Memory scanning engine using `MmCopyMemory` + `ZwQuerySystemInformation` |
| `0x140A47800` | `CiValidation_CodeIntegrityCheck` | 2,372 | Code integrity validation pipeline using `CiValidateFileObject` |
| `0x140A6EBC2` | `CiValidateFileObject_Handler` | 30,000 | Direct caller of `CiValidateFileObject` (4x) and `ZwQuerySystemInformation` (4x) — largest detection function |
| `0x140A5BB74` | `LargeRoutine_70KB_MainLogicHub` | 70,696 | Massive obfuscated logic hub |
| `0x140A51690` | `MajorDetectionRoutine_31KB` | 31,233 | Major detection routine |
| `0x140A3BB9C` | `LargeRoutine_22KB_DetectionLogic` | 22,729 | Detection logic |
| `0x140A32D60` | `LargeRoutine_20KB_ScanOrTelemetry` | 20,376 | Scan or telemetry processing |
| `0x140A2D39C` | `LargeRoutine_16KB_ProcessingEngine` | 16,130 | Processing engine |

---

## 3. Obfuscation & Anti-Analysis

Ricochet employs **multiple layers of obfuscation** that make static analysis extremely difficult. Most large functions fail Hex-Rays decompilation entirely.

### 3.1 Control Flow Flattening (CFF)

Every non-trivial function exhibits CFF:
- Basic blocks are scattered across the entire binary address space (jumps from `0x140A2xxxx` to `0x140C4xxxx`)
- Functions decompile to `JUMPOUT(addr)` stubs
- Indirect jumps via `jmp qword ptr [rax]` after runtime pointer computation

**Example** from `CiValidation_CodeIntegrityCheck` disassembly:
```asm
0x140A47800: jmp     sub_140C4B47E           ; immediate dispatch to distant code
0x140A47822: jmp     loc_140A47F11           ; scattered basic blocks
0x140A47854: jmp     loc_140A226C3           ; cross-section jump
0x140A47862: jmp     loc_140A75575           ; another distant target
0x140A47887: jmp     sub_140C4919D           ; yet another distant block
```

### 3.2 Mixed Boolean Arithmetic (MBA)

Constant values are obfuscated using XOR, ADD, SUB, and ROT operations:

```asm
mov     rcx, 3041A48534F0E6D8h      ; obfuscated constant
sub     rax, rcx                      ; decoded at runtime

mov     rcx, 0AA73915200000001h       ; large MBA constant
mov     r14, 2A71905200000000h        ; paired constant
or      rdx, r9
add     rdx, rcx
xor     rax, r11
ror     rcx, 13h                      ; rotation-based obfuscation
```

### 3.3 Import Address Obfuscation

Import calls are obfuscated through multiple mechanisms:

1. `DriverEntry_0` contains a **relocation fixup loop** that processes **658 entries** at `0x140C370F8`:
   ```c
   for (k = 658LL; k; k = (unsigned int)(k - 1))
       *v5++ += 0x140000000LL;    // add image base to VM handler entries
   ```
   *Note: These 658 entries were later identified as **VM opcode handler addresses** (see Section 18.1), not import dispatch entries.*
2. A secondary **function pointer dispatch table** at `0x1405Dxxxx` holds obfuscated offsets for indirect calls
3. Some imports ARE called directly (e.g., `call cs:IoCreateDevice`) but wrapped in heavy stack manipulation and CFF (see Section 14.5)
4. Most imports show **zero xrefs** in IDA because calls go through the VM bytecode interpreter or indirect dispatch

**Proof**: `ObRegisterCallbacks`, `PsSetLoadImageNotifyRoutine`, `KdDisableDebugger`, `MmGetSystemRoutineAddress`, `EtwRegister`, `KeIpiGenericCall`, and `ExGetFirmwareEnvironmentVariable` all show **0 direct xrefs** — but are clearly used given the driver's behavior.

Only a handful of imports have direct call xrefs (likely pre-obfuscation or different code paths):
- `PsSetCreateProcessNotifyRoutineEx` → 2 call sites
- `CiValidateFileObject` → 4 call sites (from `CiValidateFileObject_Handler`)
- `MmCopyMemory` → 12 call sites (from `CoreScanEngine_MmCopyMemory` and others)
- `ZwQuerySystemInformation` → 11 call sites
- `BCryptCreateHash` → 1 call site
- `BCryptVerifySignature` → 1 call site

### 3.4 Anti-Disassembly

Embedded junk bytes and encoded instructions to confuse linear disassemblers:
```asm
0x140A478C2: db 0CCh                  ; INT3 (breakpoint trap)
0x140A478C3: db 0EBh, 51h             ; encoded JMP as raw data bytes
```

### 3.5 String Encryption

**All operational strings are encrypted.** The only plaintext strings in the binary are:
- Import function names (required by PE loader)
- Section names (`.text`, `.rdata`, etc.)
- PDB path: `Randgrid.pdb`

No strings for "cheat", "ban", "detect", "hook", "inject", "hack", or any operational terms exist in plaintext. All runtime strings are decrypted on-the-fly.

### 3.6 Stack Manipulation

Some functions exhibit stack frame manipulation that breaks decompilation:
```
// positive sp value has been detected, the output may be wrong!
```
This indicates intentional stack pointer manipulation as an anti-analysis technique.

---

## 4. Import Analysis

### 4.1 Module Summary

| Module | Import Count | Purpose |
|--------|-------------|---------|
| **ntoskrnl.exe** | 672 | Windows NT kernel executive |
| **HAL.dll** | 4 | Hardware Abstraction Layer |
| **ci.dll** | 2 | Code Integrity (undocumented) |
| **cng.sys** | 10 | Cryptography Next Generation |
| **TOTAL** | **688** | |

672 imports from ntoskrnl alone is **exceptionally large** — most kernel drivers import 30-100 functions. This suggests either:
1. Link-time code generation pulling in full WDK surfaces (KTM, PnP, Power)
2. Intentional import table inflation as an anti-analysis/anti-signature measure
3. Actual broad functionality spanning multiple kernel subsystems

### 4.2 Imports by Category

#### Process & Thread Monitoring (18 imports)
| Import | Anti-Cheat Role |
|--------|----------------|
| `PsSetCreateProcessNotifyRoutine` | Legacy process creation callback |
| `PsSetCreateProcessNotifyRoutineEx` | Extended process creation callback (can deny creation) |
| `PsSetCreateThreadNotifyRoutine` | Thread creation monitoring (injection detection) |
| `PsSetLoadImageNotifyRoutine` | DLL/image load monitoring (injection detection) |
| `PsLookupProcessByProcessId` | EPROCESS lookup for process inspection |
| `PsLookupThreadByThreadId` | Thread inspection |
| `PsGetProcessPeb` | Access PEB — loaded modules, command line |
| `PsGetProcessCreateTimeQuadPart` | Process age verification |
| `PsLoadedModuleList` | Walk kernel module list |
| `SeLocateProcessImageName` | Get image path from EPROCESS |

#### Object & Handle Filtering (16 imports)
| Import | Anti-Cheat Role |
|--------|----------------|
| `ObRegisterCallbacks` | **Core AC mechanism**: intercepts `OpenProcess`/`OpenThread` to strip `PROCESS_VM_READ`/`PROCESS_VM_WRITE` from cheat tools |
| `ObUnRegisterCallbacks` | Cleanup |
| `ObReferenceObjectByName` | Lookup driver objects by name (detect cheat drivers) |
| `ObReferenceObjectByHandle` | Validate handle targets |
| `IoDriverObjectType` | Type reference for driver object lookup |

#### Memory Scanning (34 imports)
| Import | Anti-Cheat Role |
|--------|----------------|
| `MmCopyMemory` | **12 call sites** — read arbitrary physical/virtual memory, bypass VAD protections |
| `MmGetPhysicalAddress` | Virtual → physical translation for DMA/physical scanning |
| `MmMapIoSpace` / `MmUnmapIoSpace` | Map physical memory into virtual space |
| `MmIsAddressValid` | Safe address probing before scans |
| `MmSecureVirtualMemory` | Lock memory regions against modification |
| `ZwQueryVirtualMemory` | Query process memory layout |
| `MmProbeAndLockPages` | Lock physical pages for scanning |
| `MmAllocateContiguousMemory` (4 variants) | Physically contiguous allocation — DMA or hypervisor use |

#### Code Integrity (2 imports — ci.dll)
| Import | Anti-Cheat Role |
|--------|----------------|
| `CiValidateFileObject` | **Undocumented** — validate code integrity/signature of file objects. Called 4 times from `CiValidateFileObject_Handler`. Very few legitimate drivers use this. |
| `CiFreePolicyInfo` | Free CI policy data |

#### Cryptography (10 imports — cng.sys)
| Import | Anti-Cheat Role |
|--------|----------------|
| `BCryptVerifySignature` | Verify digital signatures on game/driver binaries |
| `BCryptImportKeyPair` | Import asymmetric keys (likely Activision's signing key) |
| `BCryptCreateHash` / `BCryptHashData` / `BCryptFinishHash` | Hash computation (file integrity, telemetry hashing) |
| `BCryptOpenAlgorithmProvider` | Algorithm initialization |

#### Telemetry — ETW (9 imports)
| Import | Role |
|--------|------|
| `EtwRegister` / `EtwUnregister` | Register/unregister ETW provider |
| `EtwWrite` / `EtwWriteTransfer` / `EtwWriteEx` / `EtwWriteString` | Write telemetry events |
| `EtwEventEnabled` / `EtwProviderEnabled` | Check if consumers are listening |
| `EtwActivityIdControl` | Activity correlation |

#### Telemetry — WMI (22+ imports)
Full WMI surface including `IoWMIRegistrationControl`, `IoWMIWriteEvent`, `IoWMIQueryAllData`, `IoWMISetSingleInstance`, `IoWMISetNotificationCallback`, etc.

#### Telemetry — PCW (5 imports)
`PcwRegister`, `PcwUnregister`, `PcwCreateInstance`, `PcwCloseInstance`, `PcwAddInstance` — Performance Counter for Windows integration.

#### Anti-Debug (3 imports)
| Import | Role |
|--------|------|
| `KdDisableDebugger` | Disable kernel debugger at runtime |
| `KdEnableDebugger` | Re-enable after integrity check |
| `KdDebuggerNotPresent` | Global variable — check debugger presence |

#### System Information (17 imports)
| Import | Role |
|--------|------|
| `ZwQuerySystemInformation` | **11 call sites** — enumerate loaded drivers, processes, handles |
| `ExIsProcessorFeaturePresent` | CPU feature detection |
| `ExGetFirmwareEnvironmentVariable` | **UEFI variable access** — rare, discussed below |
| `IoGetBootDiskInformation` | Disk info for system fingerprinting |

#### Driver Control (6 imports)
| Import | Role |
|--------|------|
| `ZwLoadDriver` / `ZwUnloadDriver` | Dynamically load/unload drivers |
| `IoRegisterBootDriverCallback` | Monitor boot-start driver loading |
| `MmGetSystemRoutineAddress` | **Dynamic API resolution** — resolve any kernel export at runtime without import table entry |

#### Kernel Transaction Manager — KTM (53 imports)
**Extremely unusual** — 53 imports spanning `NtCreate/Open/Query/Commit/Rollback` for TransactionManager, Transaction, Enlistment, and ResourceManager, plus full `Zw*` and `Tm*` equivalents. 

Possible purposes:
1. Detect cheat tools using transactional NTFS/registry operations for stealth
2. Anti-tamper mechanism — atomic rollback if integrity checks fail
3. WDK static library artifact pulling in full KTM surface

#### Hardware Performance Counters (4 imports — HAL)
| Import | Role |
|--------|------|
| `HalAllocateHardwareCounters` | Allocate PMC (Performance Monitoring Counters) |
| `HalFreeHardwareCounters` | Release PMC |
| `KeSetHardwareCounterConfiguration` | Configure which events to monitor |
| `KeQueryHardwareCounterConfiguration` | Query current PMC config |

PMCs can detect:
- Timing anomalies from hooks/patches (instruction count differences)
- Virtualization (abnormal VM exit counts)
- Code modification (branch misprediction patterns)

#### Inter-Processor Interrupt (1 import)
| Import | Role |
|--------|------|
| `KeIpiGenericCall` | Broadcast function call to ALL processors simultaneously — ensures no CPU is executing cheat code during critical checks |

#### UEFI / Firmware (2 imports)
| Import | Role |
|--------|------|
| `ExGetFirmwareEnvironmentVariable` | Read UEFI NVRAM variables |
| `ExSetFirmwareEnvironmentVariable` | Write UEFI NVRAM variables |

Possible uses:
- Detect UEFI-level rootkits/cheats
- Persist hardware ban data across OS reinstalls
- Check Secure Boot status
- Detect boot-kit tampering

---

## 5. Driver Initialization Flow

### 5.1 Entry Point Chain

```
DriverEntry (0x140C3C000) — thunk
  └─→ DriverEntry_0 (0x14045243C) — obfuscated real entry
        ├─ InterlockedCompareExchange spin lock at global (0x140AB1B2C + 216)
        ├─ XOR-decode pointers: 0x13FFBF3A6 ^ 0x7FFBF3A6 = base region
        ├─ Store current thread + entry point info
        ├─ Relocation fixup loop: 658 entries at 0x140C370F8 += 0x140000000
        ├─ Resolve dispatch table pointers
        └─ jmp qword ptr [rax] → real init (likely RandgridInit_CallbackRegistration)
```

### 5.2 Initialization (RandgridInit_CallbackRegistration @ 0x140C46DF7)

This function:
1. Calls `PsSetCreateProcessNotifyRoutineEx` → registers `NotifyRoutine`
2. References `ZwQuerySystemInformation` (3 calls) — enumerates loaded drivers at startup
3. Sets up the dispatch table at `0x1405Dxxxx`
4. Likely calls `ObRegisterCallbacks` (through dispatch table) for handle filtering
5. Likely registers `PsSetLoadImageNotifyRoutine` for image load monitoring
6. Initializes ETW provider via `EtwRegister`

### 5.3 Callback Registration Table

At `0x1405D74E0`, a data table references `NotifyRoutine` and other callback functions. This table uses obfuscated offsets that are fixed up during the relocation loop in `DriverEntry_0`.

---

## 6. Detection Vectors

### 6.1 Process Monitoring

**Callback:** `PsSetCreateProcessNotifyRoutineEx` → `NotifyRoutine` → `ProcessNotifyCallback_Real`

**Flow:**
```
ProcessNotifyCallback_Real (0x140A59438)
  ├─ Receives: PEPROCESS, ProcessId, PPS_CREATE_NOTIFY_INFO
  ├─ On process create: inspect process image, command line, parent
  ├─ Can DENY process creation (CreateInfo->CreationStatus = STATUS_ACCESS_DENIED)
  └─ On process exit: cleanup monitoring state
```

**What it detects:**
- Known cheat process names/hashes
- Suspicious parent-child process relationships
- Unsigned or tampered executables attempting to launch
- Processes attempting to interact with the game

### 6.2 Handle Filtering (ObRegisterCallbacks)

**Purpose:** Intercepts every `OpenProcess`/`OpenThread` call system-wide.

**Detection mechanism:**
- When any process tries to open a handle to the game process, the callback fires
- Strips dangerous access rights: `PROCESS_VM_READ`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, `PROCESS_CREATE_THREAD`
- Without these rights, external cheat tools cannot read/write game memory or inject threads
- Logs the attempting process for telemetry

**Bypass difficulty:** High — requires kernel-level intervention or direct syscall with pre-existing handle.

### 6.3 Image Load Monitoring (PsSetLoadImageNotifyRoutine)

**Purpose:** Notified when any DLL/EXE loads into any process.

**What it detects:**
- DLL injection into the game process
- Known cheat DLLs loaded anywhere on the system
- Unsigned/tampered modules loaded into game process
- Manual-mapped images (by monitoring for suspicious memory regions without corresponding loaded modules)

### 6.4 Memory Scanning Engine

**Core function:** `CoreScanEngine_MmCopyMemory` @ `0x140A210B2` (16,933 bytes)

**Capabilities:**
- Uses `MmCopyMemory` (12 call sites across the binary) to read physical and virtual memory
- Can bypass VirtualProtect and VAD-level protections by reading physical pages directly
- Uses `ZwQuerySystemInformation` to enumerate all loaded drivers for signature scanning
- Uses `MmGetPhysicalAddress` for virtual-to-physical translation

**What it scans for:**
- Known cheat driver signatures in kernel memory
- Modified/hooked system functions
- Suspicious kernel memory allocations (pools with specific tags)
- Unsigned drivers in the loaded module list
- Integrity violations in game process memory

### 6.5 Code Integrity Validation

**Functions:**
- `CiValidation_CodeIntegrityCheck` @ `0x140A47800`
- `CiValidateFileObject_Handler` @ `0x140A6EBC2`
- `CiValidate_TrampolineWrapper` @ `0x140A2A987`

**Mechanism:**
1. Uses the **undocumented** `CiValidateFileObject` API from `ci.dll` (Code Integrity module)
2. Called 4 times from `CiValidateFileObject_Handler`, which also calls `ZwQuerySystemInformation` 4 times
3. Validates digital signatures on loaded drivers and executables
4. Can detect:
   - Unsigned drivers
   - Drivers with revoked certificates  
   - Test-signed drivers (unless test signing is enabled)
   - Modified/patched signed binaries

### 6.6 Signature Verification (BCrypt)

**Functions:**
- `BCrypt_VerifySignature_Caller` @ `0x140344817`
- `BCryptHash_InitHashOperation` @ `0x14032224F`

**Mechanism:**
1. `BCryptImportKeyPair` — imports Activision's public key
2. `BCryptCreateHash` / `BCryptHashData` / `BCryptFinishHash` — compute hash of target binary
3. `BCryptVerifySignature` — verify hash against expected signature

**Purpose:** Independent signature verification outside of Windows CI — verifies game files and potentially the AC driver itself haven't been tampered with.

### 6.7 Driver Enumeration

**Imports:** `ZwQuerySystemInformation` (SystemModuleInformation), `PsLoadedModuleList`, `ObReferenceObjectByName`

**What it checks:**
- Complete list of loaded kernel modules
- Driver objects by name (e.g., checking for `\Driver\KnownCheatDriver`)
- Module base addresses, sizes, and load order
- Cross-references against known cheat driver signatures/names

---

## 7. Cryptography & Signature Verification

### 7.1 CNG Crypto Stack

The driver imports **10 CNG functions** providing:

**Hashing pipeline:**
```
BCryptOpenAlgorithmProvider → BCryptCreateHash → BCryptHashData → BCryptFinishHash → BCryptDestroyHash
```
Likely algorithms: SHA-256 or SHA-384 (standard for code signing)

**Signature verification pipeline:**
```
BCryptOpenAlgorithmProvider → BCryptImportKeyPair → BCryptVerifySignature → BCryptDestroyKey
```
Likely algorithm: RSA or ECDSA

### 7.2 Code Integrity (ci.dll)

The **undocumented** `CiValidateFileObject` function:
- Takes a file object and validates its embedded digital signature
- Returns policy information via `CiFreePolicyInfo`
- Called from `CiValidateFileObject_Handler` which makes 3 separate calls — likely checking multiple certificate chains or validation levels
- This is the same mechanism Windows uses internally to validate driver signatures

### 7.3 Dual Verification

Ricochet performs **two independent signature checks**:
1. **Windows CI** — via `CiValidateFileObject` (system trust chain)
2. **Custom BCrypt** — via `BCryptVerifySignature` (Activision's own keys)

This means even if an attacker compromises a Windows trusted certificate, Ricochet's custom verification would still catch the tampered binary.

---

## 8. Telemetry & ETW Infrastructure

### 8.1 ETW Provider

Ricochet registers as an **ETW (Event Tracing for Windows) provider**:

```
EtwRegister → registers provider GUID
EtwWrite/EtwWriteTransfer/EtwWriteEx/EtwWriteString → emit events
EtwEventEnabled/EtwProviderEnabled → check if consumers are active
EtwActivityIdControl → correlate related events
```

**What gets telemetered:**
- Process creation/termination events flagged as suspicious
- Handle access attempts to protected processes
- Driver load/unload events
- Memory scan results
- Code integrity validation failures
- Timing anomalies (possible hook detection)

### 8.2 WMI Integration

22+ WMI imports provide:
- System hardware fingerprinting (`IoWMIQueryAllData`)
- Instance-level data collection (`IoWMIQuerySingleInstance`)
- Event notification (`IoWMISetNotificationCallback`, `IoWMIWriteEvent`)
- Method execution (`IoWMIExecuteMethod`)

### 8.3 Performance Counters (PCW)

5 PCW imports suggest Ricochet publishes **performance counters** that can be consumed by user-mode components:
- Scan frequency/duration
- Detection event counts
- Resource utilization metrics

### 8.4 Data Flow

```
[Kernel Driver] → ETW Events → [User-Mode AC Component] → [Network] → [Activision Backend]
                → WMI Data  → [User-Mode AC Component] → [Network] → [Activision Backend]
```

The driver itself has **no network imports** (zero WFP/TDI/WSK) — all network communication is handled by the user-mode component that consumes the kernel telemetry.

---

## 9. Anti-Debug Mechanisms

### 9.1 Kernel Debugger Control

| Import | Purpose |
|--------|---------|
| `KdDisableDebugger` | Programmatically disable the kernel debugger |
| `KdEnableDebugger` | Re-enable it (after checks pass) |
| `KdDebuggerNotPresent` | Check the global flag for debugger attachment |

**Likely flow:**
1. On initialization, check `KdDebuggerNotPresent`
2. If debugger detected, either refuse to load or call `KdDisableDebugger`
3. Periodically re-check to detect late-attach debugging
4. May re-enable briefly for internal diagnostics

### 9.2 Timing-Based Detection

- `KeQueryPerformanceCounter` (HAL) — high-resolution timing
- `KeQuerySystemTimePrecise` — precise system time
- `KeQueryUnbiasedInterruptTime` — unbiased interrupt timing
- `HalAllocateHardwareCounters` — hardware PMC access

These can detect:
- Single-stepping (timing anomalies between instructions)
- Breakpoint hits (execution time spikes)
- Debugger presence through RDTSC delta analysis
- Virtualization overhead through PMC divergence

### 9.3 Extended Processor State

- `KeSaveExtendedProcessorState` / `KeRestoreExtendedProcessorState`
- `RtlGetEnabledExtendedFeatures`

Can detect hypervisor presence by checking XSAVE/AVX state handling, which differs between bare-metal and virtualized environments.

---

## 10. Advanced Techniques

### 10.1 Physical Memory Scanning

**Import combination:** `MmGetPhysicalAddress` + `MmCopyMemory` + `MmMapIoSpace`

This enables reading memory that:
- Is protected by VirtualProtect
- Has been manually mapped (no VAD entry)
- Is hidden from virtual memory queries
- Belongs to DMA-based cheat devices

**This is the counter to DMA cheat hardware** (e.g., PCILeech) and manual-map injection techniques.

### 10.2 Inter-Processor Interrupt (IPI) Broadcast

`KeIpiGenericCall` broadcasts a function to **all processor cores simultaneously**. Uses:
- Force all CPUs to a known state during critical integrity checks
- Flush instruction caches to detect self-modifying code
- Ensure no core is executing cheat code during a scan
- Synchronize TLB flushes to prevent page-table-based hiding

### 10.3 UEFI Variable Access

`ExGetFirmwareEnvironmentVariable` / `ExSetFirmwareEnvironmentVariable` enable:
- **Hardware bans** — write ban flags to UEFI NVRAM that persist across OS reinstalls and disk wipes
- **Secure Boot verification** — read Secure Boot state variables
- **Boot-kit detection** — check for unexpected UEFI variables indicating boot-level compromise
- **Machine fingerprinting** — read SMBIOS/DMI data from firmware

### 10.4 Hardware Performance Counters (PMC)

`HalAllocateHardwareCounters` + `KeSetHardwareCounterConfiguration` enable monitoring:
- **Instructions Retired** — detect hooks that add extra instructions
- **Branch Mispredictions** — detect inline hooks (unexpected branch targets)
- **Cache Misses** — detect memory scanning tools
- **VM Exits** — detect hypervisor-based cheats

This is one of the most advanced anti-cheat detection techniques, rarely seen outside of Ricochet and a few other high-end AC solutions.

### 10.5 Boot Driver Monitoring

`IoRegisterBootDriverCallback` allows Ricochet to:
- Monitor every driver that loads during boot
- Detect cheat drivers that load before the AC
- Verify boot-time driver integrity before they fully initialize
- Combined with `IoRegisterBootDriverReinitialization` for comprehensive boot coverage

### 10.6 Dynamic API Resolution

`MmGetSystemRoutineAddress` allows resolving **any exported kernel function at runtime** without an import table entry. This means:
- The actual API surface is **significantly larger** than the 688 visible imports
- Undocumented APIs can be called without leaving import traces
- API calls can change between driver versions without recompiling the import table
- Makes static analysis incomplete by design

### 10.7 Kernel Transaction Manager (KTM)

53 KTM imports is **highly unusual** for any driver. Possible purposes:
1. **Detect transactional file hiding** — cheats using `CreateFileTransacted` to hide files
2. **Atomic anti-tamper** — transactional registry/file operations that roll back if tampered
3. **Detect TxF-based injection** — transactional NTFS operations used for stealthy file modification

---

## 11. Function Map & Renames

### Renamed Functions (Applied in IDA)

| Address | Original Name | New Name | Reason |
|---------|--------------|----------|--------|
| `0x140A59438` | `sub_140A59438` | `ProcessNotifyCallback_Real` | Real handler for process creation notifications |
| `0x140A47800` | `sub_140A47800` | `CiValidation_CodeIntegrityCheck` | Calls CiValidateFileObject chain |
| `0x140A210B2` | `sub_140A210B2` | `CoreScanEngine_MmCopyMemory` | 16KB function using MmCopyMemory + ZwQuerySystemInformation |
| `0x140A51690` | `sub_140A51690` | `MajorDetectionRoutine_31KB` | 31KB major detection function |
| `0x140A3BB9C` | `sub_140A3BB9C` | `LargeRoutine_22KB_DetectionLogic` | 22KB detection logic |
| `0x140A32D60` | `sub_140A32D60` | `LargeRoutine_20KB_ScanOrTelemetry` | 20KB scan/telemetry |
| `0x140A2D39C` | `sub_140A2D39C` | `LargeRoutine_16KB_ProcessingEngine` | 16KB processing engine |
| `0x140A5BB74` | `sub_140A5BB74` | `LargeRoutine_70KB_MainLogicHub` | 70KB main logic hub |
| `0x140A6EBC2` | `sub_140A6EBC2` | `CiValidateFileObject_Handler` | Direct CiValidateFileObject caller (4x), 30KB function |
| `0x140A2A987` | `sub_140A2A987` | `CiValidate_TrampolineWrapper` | CiValidateFileObject trampoline |
| `0x140A2B887` | `sub_140A2B887` | `CiValidate_ClearAndDispatch` | Clear + dispatch to CI validation |
| `0x140C46DF7` | `sub_140C46DF7` | `RandgridInit_CallbackRegistration` | Main init — registers callbacks |
| `0x14032224F` | `sub_14032224F` | `BCryptHash_InitHashOperation` | BCryptCreateHash caller |
| `0x140344817` | `sub_140344817` | `BCrypt_VerifySignature_Caller` | BCryptVerifySignature caller |
| `0x140A38784` | `sub_140A38784` | `MediumRoutine_3KB_CryptoOrHash` | 3KB crypto/hash related |
| `0x140A39CB8` | `sub_140A39CB8` | `MediumRoutine_6KB_SystemQuery` | 6KB system query |
| `0x140A4163C` | `sub_140A4163C` | `MediumRoutine_4KB_DriverEnum` | 4KB driver enumeration |
| `0x140A451FC` | `sub_140A451FC` | `LargeRoutine_7KB_A` | 7KB large routine A |
| `0x140A43378` | `sub_140A43378` | `LargeRoutine_7KB_B` | 7KB large routine B |

### Dispatch Table

**Location:** `0x1405D6000` - `0x1405D7600` (approximate)

This region contains obfuscated function pointer triplets used by the import dispatch system. Each entry is resolved during the 658-iteration fixup loop in `DriverEntry_0`.

---

## 12. AI / Machine Learning Indicators

### 12.1 Direct Evidence

**None found.** No imports for ML frameworks, tensor operations, or neural network inference exist in the kernel driver. No strings referencing ONNX, TensorFlow, or custom ML terms.

### 12.2 Indirect Evidence (Server-Side ML)

The telemetry infrastructure **strongly suggests server-side ML**:

1. **Rich data collection**: ETW + WMI + PCW provide structured behavioral data
2. **Activity correlation**: `EtwActivityIdControl` enables correlating events across sessions
3. **System fingerprinting**: Hardware counters, processor topology, firmware variables — all useful as ML features
4. **Behavioral telemetry**: Process creation patterns, memory access patterns, timing data — classic ML input features

### 12.3 Likely Architecture

```
[Kernel Driver: Randgrid]
    │
    ├─ Collects: process events, handle access, driver loads, memory scans
    ├─ Hashes: file integrity, code signatures
    ├─ Profiles: timing, PMC data, system topology
    │
    └─→ ETW/WMI → [User-Mode Component]
                      │
                      └─→ HTTPS → [Activision Backend]
                                      │
                                      ├─ ML Pipeline (behavioral analysis)
                                      ├─ Signature matching
                                      ├─ Statistical anomaly detection
                                      └─ Ban decision engine
```

The kernel driver is the **sensor** — it collects and transmits. The **intelligence** (detection decisions, ML inference) likely runs server-side where Activision has full control over model updates without requiring driver updates.

---

## 13. Conclusions & Attack Surface

### 13.1 Architecture Summary

Ricochet/Randgrid is a **defense-in-depth kernel sensor** with:
- 20 detection vectors running concurrently (see Section 21 for full registry)
- Heavy obfuscation making static analysis extremely difficult
- Dual signature verification (Windows CI + custom BCrypt)
- Physical memory scanning capability (counters DMA cheats)
- Comprehensive telemetry feeding likely server-side ML
- Hardware-level detection via PMC and UEFI

### 13.2 Strengths

1. **Obfuscation quality** — CFF + MBA + import obfuscation + string encryption makes reverse engineering very time-consuming
2. **Physical memory access** — counters both virtual memory hiding and DMA hardware cheats
3. **Dual signature verification** — independent of Windows certificate trust chain
4. **No network surface** — kernel driver has no network attack surface
5. **Dynamic API resolution** — actual capabilities exceed visible import table
6. **Hardware-level telemetry** — PMC and UEFI access enable detections that can't be spoofed from user-mode

### 13.3 Observations for Research

1. **Import table bloat** — 688 imports with many showing 0 xrefs suggests either WDK linkage artifacts or intentional analysis resistance
2. **68 nullsub functions** — possible disabled code paths, feature flags, or stripped debug functionality
3. **KTM surface** — 53 KTM imports is anomalous and warrants deeper investigation (likely WDK artifact)
4. **UEFI persistence** — `ExSetFirmwareEnvironmentVariable` could enable hardware bans surviving disk wipes
5. **No hypervisor imports** — despite having PMC access and contiguous memory allocation, no explicit hypervisor APIs — any hypervisor interaction would be through direct CPUID/VMCALL

### 13.4 Areas Requiring Further Analysis

- [ ] Deobfuscate the 658-entry dispatch table at `0x140C370F8` to map all import calls
- [ ] Trace `MmGetSystemRoutineAddress` usage to identify dynamically resolved APIs
- [ ] Analyze `LargeRoutine_70KB_MainLogicHub` with symbolic execution / emulation
- [ ] Identify the ETW provider GUID to correlate with user-mode consumer
- [ ] Map the UEFI variable names used for potential hardware ban persistence
- [ ] Analyze PMC configuration to determine which hardware events are monitored
- [ ] Investigate KTM usage — is it real functionality or WDK artifact?
- [ ] Trace all 12 MmCopyMemory call sites to understand scan targets

---

---

## 14. Deep Dive — Phase 2 Findings

### 14.1 Total Function Count

Analysis of the full function list reveals **~1000+ functions** total:
- **Batch 1 (0-500):** ~300 named + ~200 sub_xxx functions
- **Batch 2 (500+):** 500 functions, of which:
  - **~375 are 6-byte IAT thunks** (import address table stubs)
  - **~56 are 11-50 byte helpers/dispatchers**
  - **8 functions > 100 bytes** (the real logic)
  - **0 nullsubs** in this batch (all 68 nullsubs are in batch 1)

### 14.2 Newly Discovered Critical Functions

| Address | Name | Size | Discovery |
|---------|------|------|-----------|
| `0x140A6EBC2` | `CiValidateFileObject_Handler` | **30,000** | Actually 30KB — the largest detection function in the binary |
| `0x140A8D8A8` | `CiValidation_SignatureDB_17KB` | **17,800** | Called from CiValidateFileObject_Handler — contains page-aligned encrypted data blocks |
| `0x140A7AAF6` | `VirtualMemoryQuery_Scanner` | **2,039** | Shared VM query utility used by all 3 major detection systems |
| `0x140C4A339` | `RandgridInit_AllocSignatureDB` | — | **Successfully decompiled** — core init function that allocates and populates the signature database |
| `0x140A77E3E` | `VirtualMemoryQuery_Caller` | — | Additional VM query wrapper |

### 14.3 The Signature Database ("VALK")

**This is the most significant finding of the deep analysis.**

The function `RandgridInit_AllocSignatureDB` (0x140C4A339) was successfully decompiled and reveals the core detection data flow:

```c
void RandgridInit_AllocSignatureDB() {
    g_SignatureDB_Ptr = 0;
    size = 16936;  // 0x4228 bytes
    g_SignatureDB_State = 0;
    g_RandgridInitState = 0;

    // Pool tag: "VALK" = VALKYRIE (Norse mythology naming convention)
    PoolWithTag = ExAllocatePoolWithTag(NonPagedPool, 0x4228, 'KLAV');
    g_SignatureDB_Ptr = PoolWithTag;

    if (PoolWithTag) {
        // Copy 16,936 bytes of encrypted signature data from .data section
        memcpy(PoolWithTag, g_EncryptedSignatureData_16KB, 16936);
        KeInitializeSpinLock(&SpinLock);  // thread-safe access
        // continue initialization...
    }
    // fallback path...
}
```

**Key details:**
- **Pool tag `VALK` (0x4B4C4156)** — Valkyrie, matching the Randgrid codename
- **16,936 bytes** of encrypted data at `0x140AA6AF0` copied to NonPagedPool
- **Header: `0x0422`** (1058) — possibly entry count or version
- **SpinLock protection** — concurrent scan threads can safely read the DB
- **Consumers:**
  - `CoreScanEngine_MmCopyMemory` — reads + writes (updates?) the DB
  - `CiValidateFileObject_Handler` — reads the DB for file validation
  - `RandgridInit_AllocSignatureDB` — creates and initializes the DB

### 14.4 The Global Configuration Block

A critical data area at `0x140C3AE00` serves as the **driver-wide configuration and state block**:

| Offset | Name | Value | References | Purpose |
|--------|------|-------|------------|---------|
| `+0x00` | `g_RandgridConfigFlags` | `0x02` | Checked in CFF dispatch | Bit flags controlling active features |
| `+0xD8` | `g_RandgridInitState` | `0x00` (init) | **34 locations** | Central init state — gates ALL detection routines |

**`g_RandgridInitState` cross-reference map (34 refs):**
- `CoreScanEngine_MmCopyMemory` — 4 reads
- `CiValidateFileObject_Handler` — 14 reads + 1 write
- `CiValidation_CodeIntegrityCheck` — 1 read
- `RandgridInit_CallbackRegistration` — 5 reads + 1 write
- Other helpers — 8 reads + 1 write

Every detection routine checks `g_RandgridInitState` before executing. If it's not set (not initialized), detection is bypassed. This is the **master kill switch**.

### 14.5 Obfuscated Import Call Pattern (Decoded)

Disassembly of `DeviceCreation_IoCreateDevice` (0x1402B9872) reveals the exact pattern used for obfuscated import calls:

```asm
; === PRE-CALL: restore parameters from obfuscated stack ===
pop     rax                     ; restore register
popfq                           ; restore CPU flags
pop     rcx                     ; load 1st parameter (DriverObject)

; === THE ACTUAL IMPORT CALL ===
call    cs:IoCreateDevice       ; direct IAT call

; === POST-CALL: CFF dispatch ===
jmp     loc_1404548A9           ; jump to distant continuation block

; === DEAD ZONE: encrypted padding data ===
dq 3BD4969DD401895Fh, ...      ; junk/encrypted data between blocks

; === POST-CALL OBFUSCATION: opaque register shuffling ===
pushfq                          ; save flags
push    r11                     ; save register
sub     rsp, 8                  ; adjust stack
mov     [rsp], r14              ; shuffle registers...
; [extensive register/stack manipulation to obscure state]
```

**Pattern summary:**
1. Parameters are loaded via `pop` from a pre-prepared stack layout
2. CPU flags are saved/restored around calls (`pushfq`/`popfq`)
3. The actual import call is a direct `call cs:ImportName` through the IAT
4. After the call, CFF immediately jumps to a distant basic block
5. Dead zones between blocks contain encrypted data padding
6. Post-call code performs extensive opaque register shuffling

### 14.6 CiValidateFileObject_Handler — The 30KB Colossus

The `CiValidateFileObject_Handler` at 30,000 bytes is the single largest detection function. It:

- Calls `CiValidateFileObject` (ci.dll) — **4 times** for layered validation
- Calls `ZwQuerySystemInformation` — **4 times** for driver/system enumeration
- Calls `PsGetProcessPeb` — **2 times** for process inspection via PEB
- Calls `ZwQueryVirtualMemory` — through `VirtualMemoryQuery_Scanner`
- References `g_RandgridInitState` — **14 times** (most of any function)
- References `g_SignatureDB_Ptr` — reads the signature database
- Calls `CiValidation_SignatureDB_17KB` — which contains page-aligned encrypted lookup tables

**This function is the comprehensive file/driver integrity engine** — it validates loaded drivers and executables through multiple methods simultaneously:
1. Windows Code Integrity signature validation
2. System information enumeration to detect suspicious modules  
3. PEB inspection for loaded DLL analysis
4. Virtual memory region queries for injection detection
5. Signature database lookups for known-bad patterns

### 14.7 658-Entry Table Structure (Decoded)

The table at `0x140C370F8` contains **658 QWORD entries** that are **relative addresses** before fixup:

```
Entry 0:  0x0000000000 0B005C → +0x140000000 = 0x1400B005C (code)
Entry 1:  0x0000000000 0B0061 → +0x140000000 = 0x1400B0061 (code)
Entry 2:  0x0000000000 0AE565 → +0x140000000 = 0x1400AE565 (code)
Entry 3:  0x0000000000 0AE56A → +0x140000000 = 0x1400AE56A (code)
...
```

The entries come in **pairs** (5-byte spacing between partners), forming **329 handler pairs**.

Total table size: **658 × 8 = 5,264 bytes**.

*Note: Initially interpreted as import dispatch entries. Later analysis (Section 18.1) revealed these are **VM opcode handler addresses** for the custom bytecode interpreter, not import call sites.*

### 14.8 CiValidation_SignatureDB_17KB — Encrypted Lookup Tables

The 17.8KB function at `0x140A8D8A8` is unique in the binary:
- First instruction: `jmp sub_140517A1B` (CFF dispatch)
- Followed by **massive `dq` data blocks** at **page-aligned intervals** (0x1000 apart):
  - `0x140A8E8B0`: `dq 0C97ED3BA6212BAACh, ...`
  - `0x140A8F8B0`: `dq 997516A073EA3FE5h, ...`
  - `0x140A908B0`: `dq 0C97D8264B983B855h, ...`
  - `0x140A918B0`: `dq 0A06047056C8E114Ch, ...`

These page-aligned encrypted blocks are likely:
- FNV-1a hash comparison tables (matching the hashing method confirmed in Section 18.3)
- Encrypted configuration data for each detection module
- Bloom filter or lookup table for fast pattern matching

The page alignment suggests they may be mapped separately for performance (cache-line optimization or MDL-based access patterns).

### 14.9 Updated Call Graph

```
DriverEntry (thunk)
  └─→ DriverEntry_0 (obfuscated)
        ├─ Relocation fixup: 658 entries += 0x140000000
        └─→ RandgridInit_CallbackRegistration
              ├─ RandgridInit_AllocSignatureDB
              │     ├─ ExAllocatePoolWithTag("VALK", 16936)
              │     ├─ memcpy(g_EncryptedSignatureData_16KB)
              │     ├─ KeInitializeSpinLock
              │     └─ Set g_RandgridInitState
              │
              ├─ PsSetCreateProcessNotifyRoutineEx → NotifyRoutine
              │     └─→ ProcessNotifyCallback_Real
              │
              ├─ ObRegisterCallbacks (via dispatch) → handle filter
              ├─ PsSetLoadImageNotifyRoutine (via dispatch) → image monitor
              ├─ IoCreateDevice → DeviceCreation_IoCreateDevice
              ├─ IofCompleteRequest (IRP handling)
              ├─ EtwRegister (via dispatch) → telemetry
              └─ ZwQuerySystemInformation (3x) → driver enumeration

CoreScanEngine_MmCopyMemory (16.9KB)
  ├─ MmCopyMemory (12 total call sites)
  ├─ ZwQuerySystemInformation (2x)
  ├─ SeLocateProcessImageName
  ├─ ZwQueryVirtualMemory (2x)
  ├─ Reads g_SignatureDB_Ptr
  └─ Reads g_RandgridInitState (4x)

CiValidateFileObject_Handler (30KB)
  ├─ CiValidateFileObject (4x)
  ├─ ZwQuerySystemInformation (4x)
  ├─ PsGetProcessPeb (2x)
  ├─ VirtualMemoryQuery_Scanner
  ├─ CiValidation_SignatureDB_17KB (encrypted lookup tables)
  ├─ Reads g_SignatureDB_Ptr
  └─ Reads g_RandgridInitState (14x!)

CiValidation_CodeIntegrityCheck (2.4KB)
  ├─ CiValidateFileObject_Handler (dispatch)
  ├─ VirtualMemoryQuery_Scanner
  └─ Reads g_RandgridInitState (1x)

BCrypt_VerifySignature_Caller
  └─ BCryptVerifySignature (custom sig verification)

BCryptHash_InitHashOperation
  └─ BCryptCreateHash (file hashing)
```

### 14.10 Additional Renamed Functions

| Address | New Name | Reason |
|---------|----------|--------|
| `0x140C4A339` | `RandgridInit_AllocSignatureDB` | Allocates and populates signature DB with "VALK" pool tag |
| `0x140A7AAF6` | `VirtualMemoryQuery_Scanner` | Shared ZwQueryVirtualMemory helper for all detection systems |
| `0x140A8D8A8` | `CiValidation_SignatureDB_17KB` | 17.8KB encrypted lookup tables for CI validation |
| `0x140A6E0F0` | `CiHelper_ValidationRoutine_A` | 356-byte CI validation helper |
| `0x140A6E729` | `CiHelper_ValidationRoutine_B` | 356-byte CI validation helper (mirror of A) |
| `0x140A77E3E` | `VirtualMemoryQuery_Caller` | VM query dispatch |
| `0x140A6EB0C` | `Init_SubRoutine_ThunkToSetup` | Init chain thunk |
| `0x1402B9872` | `DeviceCreation_IoCreateDevice` | IoCreateDevice wrapper (obfuscated pattern decoded) |
| `0x140C3AE00` | `g_RandgridConfigFlags` | Driver config flags (value 0x02) |
| `0x140C3AED8` | `g_RandgridInitState` | Master init state — 34 references |
| `0x140C3AF28` | `g_SignatureDB_Ptr` | Pointer to 16KB signature database in NonPagedPool |
| `0x140C3AF68` | `g_SignatureDB_State` | Signature DB status flag |
| `0x140AA6AF0` | `g_EncryptedSignatureData_16KB` | Embedded encrypted signature data blob |

---

## 15. Summary of All Renames Applied in IDA

### Functions (29 total)

| # | Address | Original | Renamed To |
|---|---------|----------|------------|
| 1 | `0x140A59438` | `sub_140A59438` | `ProcessNotifyCallback_Real` |
| 2 | `0x140A47800` | `sub_140A47800` | `CiValidation_CodeIntegrityCheck` |
| 3 | `0x140A210B2` | `sub_140A210B2` | `CoreScanEngine_MmCopyMemory` |
| 4 | `0x140A51690` | `sub_140A51690` | `MajorDetectionRoutine_31KB` |
| 5 | `0x140A3BB9C` | `sub_140A3BB9C` | `LargeRoutine_22KB_DetectionLogic` |
| 6 | `0x140A32D60` | `sub_140A32D60` | `LargeRoutine_20KB_ScanOrTelemetry` |
| 7 | `0x140A2D39C` | `sub_140A2D39C` | `LargeRoutine_16KB_ProcessingEngine` |
| 8 | `0x140A5BB74` | `sub_140A5BB74` | `LargeRoutine_70KB_MainLogicHub` |
| 9 | `0x140A6EBC2` | `sub_140A6EBC2` | `CiValidateFileObject_Handler` |
| 10 | `0x140A2A987` | `sub_140A2A987` | `CiValidate_TrampolineWrapper` |
| 11 | `0x140A2B887` | `sub_140A2B887` | `CiValidate_ClearAndDispatch` |
| 12 | `0x140C46DF7` | `sub_140C46DF7` | `RandgridInit_CallbackRegistration` |
| 13 | `0x14032224F` | `sub_14032224F` | `BCryptHash_InitHashOperation` |
| 14 | `0x140344817` | `sub_140344817` | `BCrypt_VerifySignature_Caller` |
| 15 | `0x140A38784` | `sub_140A38784` | `MediumRoutine_3KB_CryptoOrHash` |
| 16 | `0x140A39CB8` | `sub_140A39CB8` | `MediumRoutine_6KB_SystemQuery` |
| 17 | `0x140A4163C` | `sub_140A4163C` | `MediumRoutine_4KB_DriverEnum` |
| 18 | `0x140A451FC` | `sub_140A451FC` | `LargeRoutine_7KB_A` |
| 19 | `0x140A43378` | `sub_140A43378` | `LargeRoutine_7KB_B` |
| 20 | `0x140A8D8A8` | `sub_140A8D8A8` | `CiValidation_SignatureDB_17KB` |
| 21 | `0x140A7AAF6` | `sub_140A7AAF6` | `VirtualMemoryQuery_Scanner` |
| 22 | `0x140A6E0F0` | `sub_140A6E0F0` | `CiHelper_ValidationRoutine_A` |
| 23 | `0x140A6E729` | `sub_140A6E729` | `CiHelper_ValidationRoutine_B` |
| 24 | `0x140C4A339` | `sub_140C4A339` | `RandgridInit_AllocSignatureDB` |
| 25 | `0x140A77E3E` | `sub_140A77E3E` | `VirtualMemoryQuery_Caller` |
| 26 | `0x140A6EB0C` | `sub_140A6EB0C` | `Init_SubRoutine_ThunkToSetup` |
| 27 | `0x1402B9872` | `sub_1402B9872` | `DeviceCreation_IoCreateDevice` |
| 28 | `0x140A2C5DC` | — | (referenced g_RandgridInitState) |
| 29 | `0x140A26F49` | — | (referenced g_RandgridInitState) |

### Globals (6 total)

| # | Address | Original | Renamed To |
|---|---------|----------|------------|
| 1 | `0x140C3AE00` | `byte_140C3AE00` | `g_RandgridConfigFlags` |
| 2 | `0x140C3AED8` | `qword_140C3AED8` | `g_RandgridInitState` |
| 3 | `0x140C3AF28` | `qword_140C3AF28` | `g_SignatureDB_Ptr` |
| 4 | `0x140C3AF68` | `qword_140C3AF68` | `g_SignatureDB_State` |
| 5 | `0x140AA6AF0` | `unk_140AA6AF0` | `g_EncryptedSignatureData_16KB` |
| 6 | `0x140AB4F40` | `unk_140AB4F40` | (DriverEntry runtime data) |

---

---

## 16. Deep Dive — Phase 3: IOCTL Protocol & Communication

### 16.1 The IOCTL Dispatch Table (63+ Commands)

**Function:** `IOCTL_BuildDispatchTable_63Entries` @ `0x140C44000` (5,331 bytes) — **successfully decompiled**

This function builds a massive IOCTL dispatch table with **63+ entries**. Each entry is a 12-byte structure:

```c
struct IOCTL_Entry {
    DWORD ioctlCode;      // +0x00: IOCTL code (possibly obfuscated)
    WORD  status;          // +0x04: 0 (initialized status)
    WORD  inputSize;       // +0x06: input buffer size (28 or 32 bytes)
    WORD  outputSize;      // +0x08: output buffer size (32 or 36 bytes)
    WORD  padding;         // +0x0A: 0
};
```

**Two tiers of IOCTL commands:**

| Tier | Count | Input Size | Output Size | Purpose |
|------|-------|------------|-------------|---------|
| Tier 1 | 45 entries | 28 bytes | 32 bytes | Standard commands |
| Tier 2 | 18 entries | 32 bytes | 36 bytes | Extended commands (4 extra bytes each direction) |
| Reserved | 15 entries | 0 | 0 | Cleared/reserved slots |

**Total: 78 IOCTL entry slots** (63 populated + 15 reserved)

**Sample IOCTL codes (decimal → hex):**
| Decimal | Hex | Notes |
|---------|-----|-------|
| 612571 | 0x0009595B | First entry — possibly custom device type |
| 486118 | 0x000769E6 | Early entry |
| 649832 | 0x0009EBE8 | Tier 2 (extended) |
| 661688 | 0x000A1AB8 | Tier 2 (extended) |

These don't follow standard `CTL_CODE()` patterns cleanly, suggesting they may be **custom/obfuscated IOCTL codes** that get hashed by the MBA function before dispatch.

### 16.2 MBA Hash Function for IOCTL Obfuscation

**Function:** `MBA_Hash_IOCTLObfuscation` @ `0x140C49DA7` (356 bytes) — **successfully decompiled**

A pure **Mixed Boolean Arithmetic** hash function:

```c
uint64_t MBA_Hash_IOCTLObfuscation(uint64_t input) {
    return ~(input | 0x99F5FEBBCFFFFFCFuLL) 
         * (0xD554E80300000000uLL * (~input & 0x660A014430000030LL) + 0x3105896600000001LL)
         + (0xCBD9926471C13D9DuLL * ~(input | 0x99F5FEBBCFFFFFCFuLL) - 0x391596CD378CD513LL)
         * (0x680965E100000000LL * (~input & 0x660A014430000030LL) + 0x435B5D7100000000LL)
         + /* ... more MBA terms ... */
         + 0x5117CF2B00000000LL;
}
```

This function is mathematically equivalent to a simpler operation (likely XOR with a key or a multiply-shift hash) but expressed in MBA form to resist pattern recognition and symbolic analysis. It's used to obfuscate IOCTL code comparisons — the driver hashes incoming IOCTL codes before matching against the dispatch table.

### 16.3 IOCTL Buffer Size Validator

**Function:** `IOCTL_ValidateBufferSize` @ `0x140C49721` (60 bytes) — **successfully decompiled**

```c
void IOCTL_ValidateBufferSize(void* context, ..., int bufferSize) {
    if (bufferSize == 16 * (*(DWORD*)(context + 4) + 1)) {
        // valid — dispatch to handler
    } else {
        // invalid — reject
    }
}
```

The expected buffer size is computed as `16 * (field + 1)`, suggesting IOCTL buffers are structured as arrays of 16-byte elements. This implies the communication protocol uses fixed-size records.

### 16.4 IRP Handler

**Function:** `IRP_Handler_ValidateAndDispatch` @ `0x140C4B85C` (54 bytes) — **partially decompiled**

```c
void IRP_Handler_ValidateAndDispatch(void* context, void* irp) {
    // Uses _security_cookie (stack canary) — large 0x880 byte stack frame
    // Stores IRP pointer at stack+72
    if (irp) {
        if ((*(DWORD*)(irp + 4) & 1) == 0) {
            // Flag check — dispatch to IOCTL handler
        }
    }
    // Fallback path
}
```

The IRP flags check at `(irp+4) & 1` likely verifies the IRP hasn't been cancelled or is in a valid state before processing.

### 16.5 The Global Configuration Block (Complete Map)

The configuration block at `0x140C3AE00` is now fully mapped:

| Offset | Address | Name | Refs | Purpose |
|--------|---------|------|------|---------|
| `+0x00` | `0x140C3AE00` | `g_RandgridConfigFlags` | ~5 | Feature flags (value 0x02 = bit 1) |
| `+0xD8` | `0x140C3AED8` | `g_RandgridInitState` | **34** | Master init state — gates all detection |
| `+0xE0` | `0x140C3AEE0` | `g_ScanEngine_SpinLockOrContext` | **26** | Scan engine sync/context — used by ALL detection functions AND IOCTL dispatch |
| `+0xE8` | `0x140C3AEE8` | `g_DriverObjectPtr` | **8** | Stored DRIVER_OBJECT pointer |
| `+0xF0` | `0x140C3AEF0` | `g_ScanEngine_AuxState` | **3** | Auxiliary scan state |
| `+0x128` | `0x140C3AF28` | `g_SignatureDB_Ptr` | **5** | Pointer to 16KB sig DB in NonPagedPool |
| `+0x168` | `0x140C3AF68` | `g_SignatureDB_State` | **2** | Sig DB initialization status |

**Total global state references: ~83 cross-references** across the entire driver.

### 16.6 Additional Functions & Renames (Phase 3)

| Address | New Name | Reason |
|---------|----------|--------|
| `0x140C44000` | `IOCTL_BuildDispatchTable_63Entries` | Builds 63+ IOCTL dispatch entries — **decompiled** |
| `0x140C49DA7` | `MBA_Hash_IOCTLObfuscation` | MBA hash for IOCTL code obfuscation — **decompiled** |
| `0x140C49721` | `IOCTL_ValidateBufferSize` | Buffer size validation — **decompiled** |
| `0x140C4B85C` | `IRP_Handler_ValidateAndDispatch` | IRP handler with security cookie — **partial decompile** |
| `0x140C4B611` | `CheckDriverObject_Dispatch` | Driver object validity check |
| `0x140C48AF8` | (IOCTL entry clear) | Clears 12-byte IOCTL entry struct — **decompiled** |
| `0x140C3AEE0` | `g_ScanEngine_SpinLockOrContext` | 26-ref global sync/context |
| `0x140C3AEE8` | `g_DriverObjectPtr` | Stored DRIVER_OBJECT (8 refs) |
| `0x140C3AEF0` | `g_ScanEngine_AuxState` | Auxiliary state (3 refs) |

### 16.7 Updated Architecture: Full Communication Model

```
[Game Process (User-Mode)]
  │
  ├─ DeviceIoControl(hDevice, IOCTL_CODE, inputBuf, 28-32, outputBuf, 32-36)
  │     │
  │     ├─ 45 standard IOCTLs (28-byte input, 32-byte output)
  │     └─ 18 extended IOCTLs (32-byte input, 36-byte output)
  │
  └─→ [Kernel: Randgrid Driver]
        │
        ├─ IRP_Handler_ValidateAndDispatch
        │     ├─ Validate IRP flags
        │     ├─ IOCTL_ValidateBufferSize (16 * (n+1) check)
        │     ├─ MBA_Hash_IOCTLObfuscation (hash IOCTL code)
        │     └─ Lookup in 63-entry dispatch table
        │
        ├─ Detection IOCTLs → trigger scans
        │     ├─ CoreScanEngine_MmCopyMemory (memory scanning)
        │     ├─ CiValidateFileObject_Handler (integrity checks)
        │     └─ VirtualMemoryQuery_Scanner (VM queries)
        │
        ├─ Telemetry IOCTLs → return detection data
        │     ├─ ETW events
        │     └─ WMI data
        │
        └─ Configuration IOCTLs → update runtime state
              ├─ g_RandgridConfigFlags
              └─ g_SignatureDB updates
```

---

## 17. Cross-Reference Summary Statistics

| Entity | Total Xrefs | Significance |
|--------|-------------|--------------|
| `g_RandgridInitState` | 34 | Master kill switch |
| `g_ScanEngine_SpinLockOrContext` | 26 | Sync primitive for all detection |
| `MmCopyMemory` IAT | 12 | Physical/virtual memory scanning |
| `ZwQuerySystemInformation` IAT | 11 | System/driver enumeration |
| `g_DriverObjectPtr` | 8 | Driver self-reference |
| `g_SignatureDB_Ptr` | 5 | Signature database access |
| `CiValidateFileObject` IAT | 4 | Code integrity calls |
| `PsGetProcessPeb` IAT | 3 | PEB inspection |
| `g_ScanEngine_AuxState` | 3 | Auxiliary scan state |
| `g_SignatureDB_State` | 2 | DB status |

---

---

## 18. Deep Dive — Phase 4: VM Interpreter, Page Table Walking, Hashing

### 18.1 Custom Virtual Machine Interpreter (CRITICAL)

**The "658-entry dispatch table" is NOT an import dispatch table — it's a VM opcode handler table.**

Ricochet uses **Themida/VMProtect-style code virtualization**. The core detection logic is converted to custom bytecode and executed by a VM interpreter embedded in the driver.

**VM Architecture:**

```
VM Context (pointed to by RBP):
  +0x18:  VM accumulator / temp register
  +0x1C:  VM operand register
  +0x34:  VM register C
  +0x50:  VM instruction pointer → points to bytecode stream
  +0x7C:  VM register D
  +0x80:  VM register E
  +0xE4:  VM obfuscation key / state register
  +0x180: VM opcode / control byte
  +0x210: VM counter register
  +0x280: VM string character register (for FNV-1a)
  +0x426-0x45C: Virtualized general-purpose registers (WORD-sized)
```

**VM Handler Pattern (from disassembly at 0x1400B0F40):**
```asm
; === READ BYTECODE ===
mov     r8, [rbp+50h]         ; load VM instruction pointer
movzx   rdi, byte ptr [r8+2]  ; read next bytecode byte

; === EXECUTE OPERATION ===
xor     edi, [rcx]             ; XOR with VM register
or      [rcx], edi             ; OR result back

; === ADVANCE OPCODE KEY ===
xor     dword ptr [r11], 43484C97h  ; update obfuscation state

; === OPCODE DISPATCH ===
cmp     r10b, 9                ; compare opcode byte
jbe     next_handler           ; dispatch based on opcode value
```

**Key properties:**
- **329 handler pairs** (658 entries / 2) = 329 unique VM opcodes
- Bytecode is stored as `dq` data blocks between handlers (page-aligned at 0x1000 intervals)
- Each handler reads from the bytecode stream, operates on VM registers, then dispatches to the next handler
- The VM registers are WORD-sized, suggesting 16-bit operations internally
- Obfuscation keys (`0x43484C97`, `0x9565CA8`, etc.) are XOR'd into state on every handler execution

### 18.2 Direct Page Table Walking (CRITICAL — New Detection Vector)

**3 confirmed INVLPG + CR3 access sites:**

| Address | Context |
|---------|---------|
| `0x140C4B664` | Inside `RandgridInit_CallbackRegistration` code region |
| `0x140C4B8B4` | Same region (second occurrence) |
| `0x140A25EB1` | Inside `VirtualMemoryQuery_Scanner` code region |

**Complete page table walk sequence at 0x140C4B664:**
```asm
invlpg  byte ptr [rsi]    ; (1) flush TLB entry for target virtual address
mov     rcx, cr3           ; (2) read CR3 = physical base of PML4
mov     r15, rsi           ; (3) copy target virtual address
shr     r15, 27h           ; (4) >> 39 bits = extract PML4 index
                           ;     x64 4-level paging: bits[47:39] = PML4E
```

**At 0x140A25EB0 (pre-invlpg):**
```asm
and     eax, 1000h         ; check page-present bit (bit 12 of PTE)
invlpg  byte ptr [rsi]     ; invalidate TLB
mov     rcx, cr3            ; read page directory base
```

**What this enables:**
1. **Bypass ALL memory API hooks** — reads physical memory directly from page tables, no API calls
2. **Detect hypervisor page remapping** — compares actual PTE values vs expected
3. **Detect EPT (Extended Page Tables) manipulation** — hypervisor-based cheats that remap pages
4. **Detect hidden memory regions** — pages remapped by cheat drivers
5. **Physical memory scanning without MmCopyMemory** — completely API-independent path

**This is the most advanced memory scanning technique possible from ring 0** — it goes below even the MM subsystem.

### 18.3 FNV-1a String Hashing

**FNV-1a prime constant `0x100000001B3`** found at `0x140C3C038`, referenced from `CiValidateFileObject_Handler`.

```asm
mov     r12, 100000001B3h  ; FNV-1a 64-bit prime
jmp     loc_140A26E87      ; continue to hash loop
```

**FNV-1a hash computation (reconstructed):**
```c
uint64_t fnv1a_hash(const char* str) {
    uint64_t hash = 0xCBF29CE484222325;  // FNV offset basis
    while (*str) {
        hash ^= (uint8_t)*str++;
        hash *= 0x100000001B3;            // FNV prime
    }
    return hash;
}
```

**Used for:**
- Hashing process names for comparison against known cheat process hashes
- Hashing driver names for known-bad driver detection
- Hashing module names for DLL injection detection
- Hash comparison avoids plaintext string storage (anti-analysis)

This means the 16KB encrypted signature database likely contains **FNV-1a hashes** of known cheat tools, not plaintext names.

### 18.4 Anti-Debug Instructions Found

| Address | Instruction | Purpose |
|---------|-------------|---------|
| `0x140C3C050` | `in al, 61h` | PPI port B read — anti-VM detection |
| `0x140C3C052` | `int 3` | Breakpoint trap — crashes debuggers |
| `0x140A93627` | `int 29h` | Fast-fail — inside `__report_gsfailure` |

### 18.5 Synchronization Primitives (Updated)

IDA's type detection confirmed the real types:

| Address | Name | Type | Purpose |
|---------|------|------|---------|
| `0x140C3AEF0` | `g_ScanMutex_FastMutex1` | `_FAST_MUTEX` | First scan mutex |
| `0x140C3AF30` | `g_ScanMutex_FastMutex2` | `_FAST_MUTEX` | Second scan mutex |

Two separate FAST_MUTEX objects protect different scan operations, allowing concurrent detection on different subsystems.

### 18.6 Encrypted Signature Database Structure

**Header at `0x140AA6AF0`:**
```
Offset 0x00: 22 04 00 00 00 00 00 00  → QWORD 0x0422 (1058)
Offset 0x08: F2 4F 80 98 8C 78 FA D9  → encrypted data begins
Offset 0x10: 88 62 F6 20 0F 78 61 14  → ...
...
```

**Interpretation of header 0x0422:**
- If entry count: 1058 FNV-1a hashes × 8 bytes = 8464 bytes (fits within 16936)
- If entry count: 1058 entries × 16 bytes (hash + metadata) = 16928 bytes (≈16936)
- Most likely: **1058 detection entries**, each 16 bytes: `{ uint64_t fnv1a_hash; uint64_t flags_or_action; }`

**Estimated signature database structure:**
```c
struct SignatureDB {
    uint64_t entryCount;  // 1058 entries
    struct {
        uint64_t nameHash;    // FNV-1a hash of process/driver/module name
        uint64_t actionFlags; // detection action (ban, flag, monitor, etc.)
    } entries[1058];
};
```

### 18.7 Complete Detection Vector Summary (Updated)

#### Confirmed with Direct Evidence (8 vectors):

| # | Vector | Evidence Level | Key Finding |
|---|--------|---------------|-------------|
| 1 | **Process Creation Monitoring** | Decompiled | `PsSetCreateProcessNotifyRoutineEx` → `ProcessNotifyCallback_Real` |
| 2 | **Code Integrity Validation** | Xrefs confirmed | `CiValidateFileObject` 4x calls, 30KB handler, FNV-1a name hashing |
| 3 | **Memory Scanning (API-based)** | 12 xrefs | `MmCopyMemory` 12 call sites + `ZwQueryVirtualMemory` 4 sites |
| 4 | **Signature Database Matching** | Decompiled | "VALK" pool tag, 16KB encrypted DB, 1058 entries, SpinLock protected |
| 5 | **Cryptographic Verification** | Xrefs confirmed | Dual verification: `CiValidateFileObject` + `BCryptVerifySignature` |
| 6 | **IOCTL Protocol (63+ commands)** | Decompiled | MBA-hashed IOCTL codes, buffer validation, dispatch table |
| 7 | **Direct Page Table Walking** | Disassembly | `invlpg` + `mov rcx, cr3` + `shr r15, 27h` (PML4 extraction) at 3 sites |
| 8 | **FNV-1a Name Hashing** | Disassembly | Prime `0x100000001B3` used by CiValidateFileObject_Handler |

#### Confirmed by Import Presence (11 vectors):

| # | Vector | Import | Confidence |
|---|--------|--------|------------|
| 9 | Handle Filtering | `ObRegisterCallbacks` | Very High |
| 10 | Image Load Monitoring | `PsSetLoadImageNotifyRoutine` | Very High |
| 11 | Thread Creation Monitoring | `PsSetCreateThreadNotifyRoutine` | Very High |
| 12 | Anti-Debug | `KdDisableDebugger` + `int 3` traps | Confirmed |
| 13 | Driver Enumeration | `ObReferenceObjectByName` + `PsLoadedModuleList` | Very High |
| 14 | UEFI/Firmware Access | `ExGet/SetFirmwareEnvironmentVariable` | High |
| 15 | Hardware Performance Counters | `HalAllocateHardwareCounters` | Medium-High |
| 16 | IPI Broadcast | `KeIpiGenericCall` | Medium-High |
| 17 | Boot Driver Monitoring | `IoRegisterBootDriverCallback` | High |
| 18 | ETW Telemetry | 9 ETW imports | Very High |
| 19 | Dynamic API Resolution | `MmGetSystemRoutineAddress` | Confirmed |

#### Total: **19 confirmed/high-confidence detection vectors**

---

## 19. Obfuscation Architecture Summary

Ricochet employs **5 layers of protection**:

```
Layer 5 (outermost): String Encryption
  └─ All operational strings encrypted at rest, decrypted on-the-fly

Layer 4: Import Obfuscation
  └─ 658 VM handler entries fix up at DriverEntry
  └─ Most imports called through indirect dispatch

Layer 3: Mixed Boolean Arithmetic (MBA)
  └─ Constants obfuscated as MBA expressions
  └─ IOCTL codes hashed through MBA function
  └─ VM handler keys XOR'd per-execution

Layer 2: Control Flow Flattening (CFF)
  └─ Basic blocks scattered across entire binary
  └─ Indirect jumps between distant code regions
  └─ Anti-disassembly bytes (INT3, encoded JMPs)

Layer 1 (innermost): Code Virtualization (VM)
  └─ Custom bytecode interpreter
  └─ 329 unique VM opcodes
  └─ Core detection logic runs as VM bytecode
  └─ VM context with 15+ virtual registers
  └─ Bytecode stored in page-aligned encrypted blocks
```

**This is one of the most heavily protected anti-cheat drivers in production.**

---

---

## 20. EnrollAIK.exe — TPM Hardware Attestation Component

### 20.1 Binary Overview

| Property | Value |
|----------|-------|
| **Filename** | `enrollaik.exe` |
| **Type** | Win64 GUI Application (WinMain) |
| **PDB Path** | `C:\workspace\nda1_branches_jup\qq_runtime\Valkyrie\EnrollAIK\x64\Release\EnrollAIK.pdb` |
| **Obfuscation** | **None** — fully decompiled |
| **Project Path** | `Valkyrie\EnrollAIK` — confirms Valkyrie is the parent project for all Ricochet components |
| **Compiler** | MSVC (MSVCP140, VCRUNTIME140) — standard C++ Release build |
| **Imports** | KERNEL32 (25), USER32 (7), ADVAPI32 (6), SHELL32 (1), MSVCP140 (25), CRT libs |

### 20.2 Key Strings (Plaintext — Not Obfuscated)

| String | Address | Significance |
|--------|---------|--------------|
| `"certreq.exe -enrollaik -f -q -machine -config "" "` | `0x140005540` | Command to enroll TPM AIK via Windows certreq |
| `"ActivisionAIK"` | `0x140005578` | Name of the TPM Attestation Identity Key |
| `"Microsoft\\Crypto\\PCPKSP"` | `0x140005518` | Platform Crypto Provider Key Storage Provider (TPM) |
| `"S-1-5-32-545"` | `0x140005588` | SID for BUILTIN\Users group |
| `"EnrollAIKWindowClass"` | (wide string) | Hidden window class name |
| `"runas"` | (wide string) | UAC elevation verb |
| `"enrollaik.exe"` | (wide string) | Self-relaunch path |

### 20.3 Internal Project Structure Revealed

The PDB path reveals the Activision internal build structure:

```
C:\workspace\
  └─ nda1_branches_jup\            ← NDA branch, "jup" codename (Jupiter?)
       └─ qq_runtime\              ← QQ runtime (internal framework codename)
            └─ Valkyrie\            ← PROJECT: Valkyrie (= Ricochet)
                 ├─ Randgrid\       ← Kernel driver (Randgrid.sys)
                 ├─ EnrollAIK\      ← TPM enrollment tool (native C++)
                 │    └─ x64\Release\EnrollAIK.pdb
                 └─ CODSecureAttestationWizard\  ← UI Wizard (.NET/C# — CoreCLR self-contained)
                      └─ Guides user through TPM attestation setup
                         Likely calls EnrollAIK.exe internally
```

**This confirms "Valkyrie" is the umbrella project** containing the kernel driver (Randgrid), the TPM enrollment tool (EnrollAIK), and the attestation wizard UI (CODSecureAttestationWizard), plus likely other components.

#### CODSecureAttestationWizard.exe — Quick Assessment

**Not anti-cheat.** This is a .NET CoreCLR self-contained application (~6MB of embedded .NET runtime) that serves as the **user-facing UI wizard** for the TPM attestation enrollment process. Key identifiers:

| Property | Value |
|----------|-------|
| **Type** | .NET 8+ self-contained single-file executable |
| **Runtime** | CoreCLR embedded (exports: `DotNetRuntimeInfo`, `g_dacTable`, `MetaDataGetDispenser`) |
| **Compression** | zlib-ng 2.2.1 (for unpacking managed assemblies) |
| **Analysis tool** | Use **dnSpy** or **ILSpy** (not IDA — managed .NET bytecode) |
| **Role** | Frontend wizard that orchestrates TPM enrollment, likely calls `enrollaik.exe` |

### 20.4 Complete Execution Flow (Fully Decompiled)

#### Phase 1: UAC Elevation Check (WinMain @ `0x140002420`)

```c
int WinMain(HINSTANCE hInstance, ...) {
    // (1) Check if running elevated
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    GetTokenInformation(hToken, TokenElevation, &isElevated, ...);
    CloseHandle(hToken);

    if (!isElevated) {
        // (2) Re-launch self with UAC elevation
        SHELLEXECUTEINFOW sei = {};
        sei.lpVerb = L"runas";              // trigger UAC prompt
        sei.lpFile = L"enrollaik.exe";      // re-launch self
        sei.nShow = SW_HIDE;                // hidden window
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        ShellExecuteExW(&sei);
        WaitForSingleObject(sei.hProcess, INFINITE);
        GetExitCodeProcess(sei.hProcess, &exitCode);
        return exitCode;
    }

    // (3) Running as admin — create hidden window and enter message loop
    WNDCLASS wc = {};
    wc.lpszClassName = L"EnrollAIKWindowClass";
    wc.lpfnWndProc = WindowProc;  // handles WM_CREATE → triggers enrollment
    RegisterClassW(&wc);
    CreateWindowExW(0, L"EnrollAIKWindowClass", ...);
    // Message loop...
}
```

#### Phase 2: TPM AIK Enrollment (sub_140001EE0 @ `0x140001EE0`)

```c
DWORD EnrollTPM_AIK() {
    // (1) Build command line
    string cmdline = "certreq.exe -enrollaik -f -q -machine -config \"\" ActivisionAIK";

    // (2) Execute certreq.exe silently (CREATE_NO_WINDOW)
    CreateProcessA(NULL, cmdline, ..., CREATE_NO_WINDOW, ..., &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);

    // (3) Accept success OR NTE_NOT_FOUND (-2146893809 = key already exists)
    if (exitCode == 0 || exitCode == NTE_NOT_FOUND) {

        // (4) Get the TPM key file path
        string keyPath = GetTPMKeyPath("ActivisionAIK");

        if (!keyPath.empty()) {
            // (5) Set ACL: grant GENERIC_READ to Users group (S-1-5-32-545)
            GetNamedSecurityInfoA(keyPath, SE_FILE_OBJECT, DACL_INFO, ..., &dacl, &sd);
            ConvertStringSidToSidA("S-1-5-32-545", &usersSid);

            EXPLICIT_ACCESS ea = {};
            ea.grfAccessPermissions = GENERIC_READ;  // 0x80000000
            ea.grfAccessMode = SET_ACCESS;            // 2
            ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea.Trustee.ptstrName = usersSid;

            SetEntriesInAclA(1, &ea, dacl, &newDacl);
            SetNamedSecurityInfoA(keyPath, SE_FILE_OBJECT, DACL_INFO, NULL, NULL, newDacl, NULL);
        }
    }
    return exitCode;
}
```

#### Phase 3: Locate TPM Key File (sub_1400011C0 @ `0x1400011C0`)

```c
string GetTPMKeyPath(string keyName) {
    // (1) Run certutil to query TPM key info
    string cmd = "certutil.exe -CSP TPM -key " + keyName;

    // (2) Create pipe to capture stdout
    CreatePipe(&hRead, &hWrite, &sa, 0);
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    // (3) Execute certutil with stdout redirected to pipe
    startupInfo.hStdOutput = hWrite;
    startupInfo.hStdError = hWrite;
    CreateProcessA(NULL, cmd, ..., CREATE_NO_WINDOW, ..., &pi);

    // (4) Read all output from pipe
    string output;
    while (ReadFile(hRead, buffer, 4095, &bytesRead, NULL) && bytesRead > 0) {
        output += string(buffer, bytesRead);
    }
    WaitForSingleObject(pi.hProcess, INFINITE);

    // (5) Parse output: find line containing "Microsoft\\Crypto\\PCPKSP"
    istringstream stream(output);
    string line;
    while (getline(stream, line)) {
        if (line.find("Microsoft\\Crypto\\PCPKSP") != string::npos) {
            // (6) Trim whitespace and quotes from the path
            return trim(line);
        }
    }
    return "";  // not found
}
```

### 20.5 TPM Attestation Identity Key — Technical Details

**What is an AIK?**

An Attestation Identity Key (AIK) is an RSA key pair generated inside the TPM (Trusted Platform Module) chip. The private key **never leaves the TPM** — all cryptographic operations happen inside the chip's secure enclave.

**What "ActivisionAIK" enables:**

| Capability | Description |
|-----------|-------------|
| **Hardware Identity** | Creates a unique, unforgeable cryptographic identity for each physical machine |
| **Remote Attestation** | Game client can prove to Activision servers that it's running on specific hardware |
| **Tamper Detection** | TPM can attest that the boot chain hasn't been modified |
| **Hardware Bans** | If Activision bans the AIK, the machine is permanently banned — no OS reinstall, disk swap, or BIOS flash can change the TPM's identity |
| **Anti-Spoof** | Cannot be cloned to another machine — TPM keys are hardware-bound |

**ACL modification purpose:**

By default, TPM key files in `Microsoft\Crypto\PCPKSP` are only readable by SYSTEM and Administrators. EnrollAIK grants `GENERIC_READ` to the `Users` group (SID `S-1-5-32-545`) so that the game process (running as a normal user) can access the TPM key for attestation without requiring admin privileges.

### 20.6 Integration with Ricochet Kernel Driver

```
┌─────────────────────────────────────────────────────┐
│                VALKYRIE ECOSYSTEM                    │
│                                                      │
│  ┌──────────────────┐     ┌──────────────────────┐  │
│  │  EnrollAIK.exe   │     │  Randgrid (kernel)   │  │
│  │  (one-time setup)│     │  (kernel driver)     │  │
│  │                  │     │                      │  │
│  │  1. Create AIK   │     │  • Process monitor   │  │
│  │  2. Set ACL      │     │  • Memory scanning   │  │
│  │                  │     │  • CI validation     │  │
│  └────────┬─────────┘     │  • Handle filtering  │  │
│           │               │  • Page table walk   │  │
│           ▼               │  • 1058 sig DB       │  │
│  ┌──────────────────┐     │  • 63 IOCTLs         │  │
│  │  TPM Chip (HW)   │     │  • VM interpreter    │  │
│  │                  │     └──────────┬───────────┘  │
│  │  "ActivisionAIK" │               │ IOCTLs       │
│  │  (private key)   │               ▼               │
│  └────────┬─────────┘     ┌──────────────────────┐  │
│           │               │  User-Mode Component │  │
│           │  TPM Sign     │  (game process)      │  │
│           └──────────────►│                      │  │
│                           │  • Read AIK via PCPKSP│  │
│                           │  • Sign attestation  │  │
│                           │  • Consume ETW/IOCTL │  │
│                           │  • HTTPS → servers   │  │
│                           └──────────┬───────────┘  │
│                                      │               │
└──────────────────────────────────────┼───────────────┘
                                       │
                                       ▼
                            ┌──────────────────────┐
                            │  Activision Backend  │
                            │                      │
                            │  • Verify AIK attestation
                            │  • ML behavioral analysis
                            │  • Ban decision engine
                            │  • Hardware ban registry
                            └──────────────────────┘
```

### 20.7 Hardware Ban Mechanism (Reconstructed)

Based on the combined analysis of Randgrid (kernel driver) and EnrollAIK:

```
ENROLLMENT (one-time):
  1. EnrollAIK.exe runs as admin (UAC elevation)
  2. certreq.exe -enrollaik creates "ActivisionAIK" in TPM
  3. ACL modified: Users group gets GENERIC_READ on key file
  4. TPM generates RSA key pair — private key locked in hardware

RUNTIME (every game session):
  1. Game process opens TPM key via Microsoft\Crypto\PCPKSP
  2. Game creates attestation blob (system info, timestamps, etc.)
  3. TPM signs the blob with ActivisionAIK private key
  4. Signed blob sent to Activision servers via HTTPS
  5. Server verifies signature with stored public key
  6. Server checks if this AIK is in the ban registry

DETECTION + BAN:
  1. Kernel driver (Randgrid) detects cheating via 19 detection vectors
  2. Telemetry sent via ETW/IOCTL → user-mode → servers
  3. Server-side ML confirms detection
  4. Server bans the ActivisionAIK public key
  5. ALL future attestation attempts from this TPM are rejected
  6. Player cannot:
     - Reinstall Windows (TPM key persists)
     - Swap hard drives (key is in TPM chip)
     - Flash BIOS (TPM is a separate chip)
     - Create new accounts (same TPM = same ban)
     - Only option: replace motherboard (new TPM chip)

ADDITIONAL PERSISTENCE (from kernel driver):
  - ExGet/SetFirmwareEnvironmentVariable → UEFI NVRAM ban flags
  - Combined TPM + UEFI = dual hardware ban mechanism
```

### 20.8 EnrollAIK Function Renames Applied

| Address | Original | Renamed To | Notes |
|---------|----------|------------|-------|
| `0x140002420` | `WinMain` | (already named) | UAC elevation + window creation |
| `0x140001EE0` | `sub_140001EE0` | `EnrollAIK_Main` | Core enrollment: certreq + ACL setup |
| `0x1400011C0` | `sub_1400011C0` | `GetTPMKeyPath_CertUtil` | Runs certutil, parses PCPKSP path |
| `0x1400023E0` | `sub_1400023E0` | `WindowProc_EnrollAIK` | Window procedure (triggers enrollment) |

---

## 21. Final Summary — Complete Valkyrie/Ricochet Architecture

### Component Inventory

| Component | Codename | Type | Obfuscation | Purpose |
|-----------|----------|------|-------------|---------|
| `Randgrid.sys` | **Randgrid** | Kernel Driver | 5 layers (VM + CFF + MBA + imports + strings) | Detection sensor + local enforcement |
| `enrollaik.exe` | **EnrollAIK** | User-Mode EXE | None | TPM attestation key enrollment |
| User-mode component | Unknown | Unknown | Unknown | Telemetry relay + TPM attestation + network |
| Backend | Unknown | Server | N/A | ML inference + ban decisions |

### Detection Vector Registry (20 Total)

| # | Vector | Source | Confidence |
|---|--------|--------|------------|
| 1 | Process Creation Monitoring | Kernel (decompiled) | **Confirmed** |
| 2 | Code Integrity Validation (CiValidateFileObject) | Kernel (xrefs) | **Confirmed** |
| 3 | Memory Scanning (MmCopyMemory — 12 call sites) | Kernel (xrefs) | **Confirmed** |
| 4 | Signature Database (1058 FNV-1a entries, "VALK") | Kernel (decompiled) | **Confirmed** |
| 5 | Cryptographic Verification (BCrypt dual-check) | Kernel (xrefs) | **Confirmed** |
| 6 | IOCTL Protocol (63+ commands, MBA hashed) | Kernel (decompiled) | **Confirmed** |
| 7 | Direct Page Table Walking (CR3 + INVLPG) | Kernel (disassembly) | **Confirmed** |
| 8 | FNV-1a Name Hashing | Kernel (disassembly) | **Confirmed** |
| 9 | Handle Filtering (ObRegisterCallbacks) | Kernel (import) | Very High |
| 10 | Image Load Monitoring (PsSetLoadImageNotifyRoutine) | Kernel (import) | Very High |
| 11 | Thread Creation Monitoring | Kernel (import) | Very High |
| 12 | Anti-Debug (KdDisableDebugger + int3) | Kernel (import + disasm) | **Confirmed** |
| 13 | Driver Enumeration (ObReferenceObjectByName) | Kernel (import) | Very High |
| 14 | UEFI/Firmware Variables (hardware ban persistence) | Kernel (import) | High |
| 15 | Hardware Performance Counters (PMC timing) | Kernel (import) | Medium-High |
| 16 | IPI Broadcast (KeIpiGenericCall) | Kernel (import) | Medium-High |
| 17 | Boot Driver Monitoring | Kernel (import) | High |
| 18 | ETW Telemetry (9 imports) | Kernel (import) | Very High |
| 19 | Dynamic API Resolution (MmGetSystemRoutineAddress) | Kernel (import) | **Confirmed** |
| 20 | **TPM Hardware Attestation (ActivisionAIK)** | **EnrollAIK (decompiled)** | **Confirmed** |

### Analysis Statistics

| Metric | Count |
|--------|-------|
| Functions renamed in IDA (kernel) | ~45 |
| Globals renamed in IDA (kernel) | ~12 |
| Functions renamed in IDA (EnrollAIK) | 4 |
| Functions successfully decompiled (kernel) | ~10 |
| Functions successfully decompiled (EnrollAIK) | **ALL** (no obfuscation) |
| Detection vectors identified | 20 |
| VM opcodes in interpreter | 329 |
| Signature DB entries | 1,058 |
| IOCTL commands | 63+ |
| Obfuscation layers (kernel) | 5 |
| Total imports analyzed | 688 (kernel) + 85 (EnrollAIK) |

---

*
This content is approximately three months old. The information presented here reflects the version available at that time and may not include the most recent updates or changes. This post is intended purely for educational purposes.
This document represents a comprehensive five-phase reverse engineering analysis of the Ricochet/Valkyrie anti-cheat ecosystem, covering the kernel driver (Randgrid) and the TPM enrollment tool (EnrollAIK.exe). The analysis revealed 20 detection vectors, a custom VM interpreter with 329 opcodes, direct page table walking, FNV-1a signature matching against 1,058 entries, a 63-command IOCTL protocol, and a TPM-based hardware attestation system ("ActivisionAIK") that enables permanent hardware bans. The kernel driver employs 5 layers of obfuscation while the enrollment tool is completely unprotected, providing valuable insight into the internal Valkyrie project structure at Activision.*
