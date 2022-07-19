#pragma once

#include <stdio.h>
#include <windows.h>

#include "ntdefs.h"
#include "syscalls.h"
#include "dinvoke.h"
#include "csr.h"

#ifdef _WIN64
 #define OSMAJORVERSION_OFFSET 0x118
 #define PEB_OFFSET 0x60
 #define READ_MEMLOC __readgsqword
#else
 #define OSMAJORVERSION_OFFSET 0xa4
 #define PEB_OFFSET 0x30
 #define READ_MEMLOC __readfsdword
#endif

#define DOS_HEADERS_SIZE 0x1000

typedef VOID(NTAPI* RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(NTAPI* RtlCreateProcessParametersEx_t)(PRTL_USER_PROCESS_PARAMETERS* pProcessParameters, PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath, PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine, PVOID Environment, PUNICODE_STRING WindowTitle, PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo, PUNICODE_STRING RuntimeData, ULONG Flags);
typedef NTSTATUS(NTAPI* RtlDestroyProcessParameters_t)(PRTL_USER_PROCESS_PARAMETERS procParams);
typedef PVOID(NTAPI* RtlAllocateHeap_t)(PVOID  HeapHandle, ULONG  Flags, SIZE_T Size);
typedef BOOL(NTAPI* RtlFreeHeap_t)(PVOID HeapHandle, ULONG  Flags, PVOID BaseAddress);

#define RtlInitUnicodeString_SW2_HASH 0x7B6E73FC
#define RtlCreateProcessParametersEx_SW2_HASH 0x5A6A1A93
#define RtlDestroyProcessParameters_SW2_HASH 0x2B02174D
#define RtlAllocateHeap_SW2_HASH 0x12B32415
#define CsrAllocateCaptureBuffer_SW2_HASH 0xE7A5EF3E
#define CsrClientCallServer_SW2_HASH 0x3A0512BB
#define RtlFreeHeap_SW2_HASH 0x29881D2C
