#pragma once

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#ifndef SW2_HEADER_H_
#define SW2_HEADER_H_

#include <windows.h>

#include "utils.h"
#include "ntdefs.h"

#define SW2_SEED 0x1337C0DE
#define SW2_ROL8(v) (v << 8 | v >> 24)
#define SW2_ROR8(v) (v >> 8 | v << 24)
#define SW2_ROX8(v) ((SW2_SEED % 2) ? SW2_ROL8(v) : SW2_ROR8(v))
#define SW2_MAX_ENTRIES 500
#define SW2_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

#ifdef _M_IX86
 // x86 has conflicting types with these functions
 #define NtClose _NtClose
 #define NtQueryInformationProcess _NtQueryInformationProcess
 #define NtCreateFile _NtCreateFile
 #define NtQuerySystemInformation _NtQuerySystemInformation
 #define NtWaitForSingleObject _NtWaitForSingleObject
 #define NtQueryInformationFile _NtQueryInformationFile
#endif
// Typedefs are prefixed to avoid pollution.

typedef struct _SW2_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
    PVOID SyscallAddress;
} SW2_SYSCALL_ENTRY, *PSW2_SYSCALL_ENTRY;

typedef struct _SW2_SYSCALL_LIST
{
    DWORD Count;
    SW2_SYSCALL_ENTRY Entries[SW2_MAX_ENTRIES];
} SW2_SYSCALL_LIST, *PSW2_SYSCALL_LIST;

typedef struct _SW2_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} SW2_PEB_LDR_DATA, *PSW2_PEB_LDR_DATA;

typedef struct _SW2_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} SW2_LDR_DATA_TABLE_ENTRY, *PSW2_LDR_DATA_TABLE_ENTRY;

typedef struct _SW2_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PSW2_PEB_LDR_DATA Ldr;
} SW2_PEB, *PSW2_PEB;

DWORD SW2_HashSyscall(
    IN PCSTR FunctionName);

PVOID GetSyscallAddress(
    IN PVOID nt_api_address,
    IN ULONG32 size_of_ntapi);

BOOL SW2_PopulateSyscallList(VOID);

BOOL local_is_wow64(VOID);

PVOID getIP(VOID);

void SyscallNotFound(VOID);

#if defined(__GNUC__)
DWORD SW2_GetSyscallNumber(IN DWORD FunctionHash) asm ("SW2_GetSyscallNumber");
PVOID SW3_GetSyscallAddress(IN DWORD FunctionHash) asm ("SW3_GetSyscallAddress");
#else
DWORD SW2_GetSyscallNumber(IN DWORD FunctionHash);
PVOID SW3_GetSyscallAddress(IN DWORD FunctionHash);
#endif

//typedef struct _IO_STATUS_BLOCK
//{
//	union
//	{
//		NTSTATUS Status;
//		VOID*    Pointer;
//	};
//	ULONG_PTR Information;
//} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

//typedef struct _UNICODE_STRING
//{
//	USHORT Length;
//	USHORT MaximumLength;
//	PWSTR  Buffer;
//} UNICODE_STRING, *PUNICODE_STRING;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

//typedef struct _OBJECT_ATTRIBUTES
//{
//	ULONG           Length;
//	HANDLE          RootDirectory;
//	PUNICODE_STRING ObjectName;
//	ULONG           Attributes;
//	PVOID           SecurityDescriptor;
//	PVOID           SecurityQualityOfService;
//} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation,
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

//typedef enum _THREADINFOCLASS
//{
//	ThreadBasicInformation,
//	ThreadTimes,
//	ThreadPriority,
//	ThreadBasePriority,
//	ThreadAffinityMask,
//	ThreadImpersonationToken,
//	ThreadDescriptorTableEntry,
//	ThreadEnableAlignmentFaultFixup,
//	ThreadEventPair_Reusable,
//	ThreadQuerySetWin32StartAddress,
//	ThreadZeroTlsCell,
//	ThreadPerformanceCount,
//	ThreadAmILastThread,
//	ThreadIdealProcessor,
//	ThreadPriorityBoost,
//	ThreadSetTlsArrayAddress,
//	ThreadIsIoPending,
//	ThreadHideFromDebugger,
//	ThreadBreakOnTermination,
//	MaxThreadInfoClass
//} THREADINFOCLASS, *PTHREADINFOCLASS;

//typedef struct _CLIENT_ID
//{
//	HANDLE UniqueProcess;
//	HANDLE UniqueThread;
//} CLIENT_ID, *PCLIENT_ID;

//typedef enum _PROCESSINFOCLASS
//{
//	ProcessBasicInformation = 0,
//	ProcessDebugPort = 7,
//	ProcessWow64Information = 26,
//	ProcessImageFileName = 27,
//	ProcessBreakOnTermination = 29
//} PROCESSINFOCLASS, *PPROCESSINFOCLASS;

typedef struct _THREAD_BASIC_INFORMATION {
  NTSTATUS                ExitStatus;
  PVOID                   TebBaseAddress;
  CLIENT_ID               ClientId;
  KAFFINITY               AffinityMask;
  KPRIORITY               Priority;
  KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID            ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG            Reserved);

EXTERN_C NTSTATUS _NtCreateUserProcess(
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
	IN ULONG ProcessFlags,
	IN ULONG ThreadFlags,
	IN PVOID ProcessParameters OPTIONAL,
	IN OUT PPS_CREATE_INFO CreateInfo,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

NTSTATUS _NtClose(
	IN HANDLE Handle);

EXTERN_C NTSTATUS _NtAlpcSendWaitReceivePort(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PVOID SendMessage OPTIONAL,
	IN OUT PVOID SendMessageAttributes OPTIONAL,
	OUT PVOID ReceiveMessage OPTIONAL,
	IN OUT PSIZE_T BufferLength OPTIONAL,
	IN OUT PVOID ReceiveMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS _NtResumeThread(
	IN HANDLE ThreadHandle,
	IN OUT PULONG PreviousSuspendCount OPTIONAL);

EXTERN_C NTSTATUS _NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS _NtCreateSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL);

EXTERN_C NTSTATUS _NtCreateProcessEx(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	IN ULONG JobMemberLevel);

EXTERN_C NTSTATUS _NtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS _NtOpenFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions);

EXTERN_C NTSTATUS _NtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

NTSTATUS _NtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesRead OPTIONAL);

NTSTATUS _NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID * BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

EXTERN_C NTSTATUS _NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T NumberOfBytesToWrite,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS _NtSetInformationProcess(
	IN HANDLE DeviceHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID ProcessInformation,
	IN ULONG Length);

EXTERN_C NTSTATUS _NtQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PTHREAD_BASIC_INFORMATION ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS _NtReadFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	OUT PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL);

#endif
