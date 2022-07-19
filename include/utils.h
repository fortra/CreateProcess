#pragma once

#include <winternl.h>
#include "output.h"

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )

#ifndef NT_SUCCESS
 #define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif


#if defined(_MSC_VER)
 #define ProcessInstrumentationCallback 40
#endif

typedef struct _linked_list
{
    struct _linked_list* next;
} linked_list, *Plinked_list;

#define intAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size)
#define intFree(addr) HeapFree(GetProcessHeap(), 0, addr)

#define RVA(type, base_addr, rva) (type)(ULONG_PTR)((ULONG_PTR) base_addr + rva)

#ifdef _WIN64
 #define CID_OFFSET 0x40
 #define PEB_OFFSET 0x60
 #define READ_MEMLOC __readgsqword
#else
 #define CID_OFFSET 0x20
 #define PEB_OFFSET 0x30
 #define READ_MEMLOC __readfsdword
#endif

BOOL is_full_path(
    IN LPCSTR filename);

VOID get_full_path(
    OUT PUNICODE_STRING full_dump_path,
    IN LPCSTR filename);

LPCWSTR get_cwd(VOID);

BOOL write_file(
    IN PUNICODE_STRING full_dump_path,
    IN PBYTE fileData,
    IN ULONG32 fileLength);

BOOL create_file(
    IN PUNICODE_STRING full_dump_path);

BOOL download_file(
    IN LPCSTR fileName,
    IN char fileData[],
    IN ULONG32 fileLength);

BOOL delete_file(
    IN LPCSTR filepath);

BOOL file_exists(
    IN LPCSTR filepath);

BOOL wait_for_process(
    IN HANDLE hProcess);

PVOID get_process_image(
    IN HANDLE hProcess);

BOOL is_lsass(
    IN HANDLE hProcess);

DWORD get_pid(
    IN HANDLE hProcess);

BOOL kill_process(
    IN DWORD pid,
    IN HANDLE hProcess);

DWORD get_lsass_pid(VOID);

BOOL remove_syscall_callback_hook(VOID);

VOID print_success(
    IN LPCSTR dump_path,
    IN BOOL use_valid_sig,
    IN BOOL write_dump_to_disk);

VOID free_linked_list(
    IN PVOID head);

PVOID allocate_memory(
    OUT PSIZE_T region_size);

VOID encrypt_dump(
    IN PVOID base_address,
    IN SIZE_T region_size);

VOID erase_dump_from_memory(
    IN PVOID base_address,
    IN SIZE_T region_size);

VOID generate_invalid_sig(
    OUT PULONG32 Signature,
    OUT PUSHORT Version,
    OUT PUSHORT ImplementationVersion);

