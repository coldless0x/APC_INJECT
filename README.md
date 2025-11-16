# APC Syscall APC Injector (Windows, C++)

A minimal, production-grade APC injector focused on clarity and reliability. It uses native ntdll system calls to allocate executable memory, write a payload, and schedule execution via Asynchronous Procedure Calls (APC). The injector also includes a LoadLibraryW APC mode so the repository can be public without shipping a real payload.

## Highlights
- Native ntdll path (syscalls): NtAllocateVirtualMemory, NtWriteVirtualMemory, NtQueueApcThread, NtTestAlert
- Immediate APC execution: queues on an on-demand suspended remote thread starting at NtTestAlert, then resumes
- Clean, minimal codebase: only 2 source files build
- Public-safe defaults: payload size is 0 by default; LoadLibraryW APC mode available
- No inline assembly; WinAPI and ntdll exports only

## Build
- Toolchain: Visual Studio 2022+ (x64), Windows SDK 10+
- Open `apc_injector.vcxproj` and build (Debug/Release x64)

## Usage
There are two supported flows – native payload APC and APC LoadLibraryW.

### 1) Native payload APC (syscall path)
- Edit `src/payload/payload.cpp` and provide your payload bytes:
  - `g_DllPayload` → array of bytes
  - `g_DllPayloadSize` → exact size
- Run:
```
sys_apc.exe [process_name]
```
- Default process if omitted: `notepad.exe`

What happens:
1. Finds PID of target process
2. Uses `NtAllocateVirtualMemory` to allocate RWX region
3. Uses `NtWriteVirtualMemory` to copy payload
4. Uses `NtQueueApcThread` to queue APC on all target threads
5. Forces execution by creating a suspended remote thread at `NtTestAlert`, queues APC on it, then `ResumeThread`

### 2) APC LoadLibraryW (no embedded bytes, public-friendly)
For repositories without embedded payloads: use LoadLibraryW APC with the path to your DLL.

This mode is provided in the alternative modular entry (previously `main.cpp`), but the current project is configured for the single-file syscall injector. To use LoadLibraryW APC in this repo, either:
- Temporarily switch the project to the modular version, or
- Adapt `sys_apc.cpp` to call LoadLibraryW (the code in `apc.cpp` shows the pattern)

LoadLibraryW flow (conceptually):
1. Allocate remote memory for wide-string path
2. Write DLL path string via `WriteProcessMemory`
3. Resolve `kernel32!LoadLibraryW`
4. Queue APC on threads with `(APC)LoadLibraryW(remoteString)`
5. Trigger with `NtTestAlert`

## Security & Behavior Notes
- APCs execute only when a thread enters an alertable state (e.g., `WaitForSingleObjectEx`, `SleepEx`). The injector forces that by using a suspended thread started at `NtTestAlert` and resuming it.
- Target process permissions: ensure injector has rights to open, allocate, write, and create threads in the target.
- Public repo safety: by default, `g_DllPayloadSize=0`. The injector exits if no bytes are provided.
- The code does not rely on inline assembly or undocumented structures; it uses exported ntdll functions.

## Troubleshooting
- "Process not found": ensure the target is running and the name matches exactly (e.g., `notepad.exe`).
- No APC execution: some targets rarely reach alertable waits. The injector creates a dedicated thread at `NtTestAlert` to force execution; if still no effect, verify AV/EDR blocks or insufficient privileges.
- Access denied: run elevated if the target is elevated or protected.
- Payload returns immediately: the sample placeholder is `{0x90, 0xC3}` (NOP; RET). Provide a real payload.

## Extending
- Replace `WriteProcessMemory` with `NtWriteVirtualMemory` in any alternate paths for consistency
- Add `NtCreateThreadEx` path if you want a non-APC fallback
- Add filesystem staging or encryption for payload if publishing beyond research purposes

## Legal
This project is for research and educational purposes only. Use responsibly and in compliance with applicable laws and policies.

## License
MIT
