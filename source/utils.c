#include "utils.h"
#include "syscalls.h"

BOOL is_full_path(
    IN LPCSTR filename)
{
    char c;

    if (filename[0] == filename[1] && filename[1] == '\\')
        return TRUE;

    c = filename[0] | 0x20;
    if (c < 97 || c > 122)
        return FALSE;

    c = filename[1];
    if (c != ':')
        return FALSE;

    c = filename[2];
    if (c != '\\')
        return FALSE;

    return TRUE;
}

VOID get_full_path(
    OUT PUNICODE_STRING full_dump_path,
    IN LPCSTR filename)
{
    wchar_t wcFileName[MAX_PATH];

    // add \??\ at the start
    wcsncpy(full_dump_path->Buffer, L"\\??\\", MAX_PATH);
    // if it is just a relative path, add the current directory
    if (!is_full_path(filename))
        wcsncat(full_dump_path->Buffer, get_cwd(), MAX_PATH);
    // convert the path to wide string
    mbstowcs(wcFileName, filename, MAX_PATH);
    // add the file path
    wcsncat(full_dump_path->Buffer, wcFileName, MAX_PATH);
    // set the length fields
    full_dump_path->Length = wcsnlen(full_dump_path->Buffer, MAX_PATH);
    full_dump_path->Length *= 2;
    full_dump_path->MaximumLength = full_dump_path->Length + 2;
}

LPCWSTR get_cwd(VOID)
{
    PVOID pPeb;
    PPROCESS_PARAMETERS pProcParams;

    pPeb = (PVOID)READ_MEMLOC(PEB_OFFSET);
    pProcParams = *RVA(PPROCESS_PARAMETERS*, pPeb, PROCESS_PARAMETERS_OFFSET);
    return pProcParams->CurrentDirectory.DosPath.Buffer;
}

BOOL file_exists(
    IN LPCSTR filepath)
{
    HANDLE hFile = NULL;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK IoStatusBlock;
    LARGE_INTEGER largeInteger;
    largeInteger.QuadPart = 0;
    wchar_t wcFilePath[MAX_PATH];
    UNICODE_STRING UnicodeFilePath;
    UnicodeFilePath.Buffer = wcFilePath;
    get_full_path(&UnicodeFilePath, filepath);

    // init the object attributes
    InitializeObjectAttributes(
        &objAttr,
        &UnicodeFilePath,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);
    // call NtCreateFile with FILE_OPEN
    NTSTATUS status = NtCreateFile(
        &hFile,
        FILE_GENERIC_READ,
        &objAttr,
        &IoStatusBlock,
        &largeInteger,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);
    if (status == STATUS_SHARING_VIOLATION)
    {
        DPRINT_ERR("The file is being used by another process");
        return FALSE;
    }
    if (status == STATUS_OBJECT_NAME_NOT_FOUND)
        return FALSE;
    if (!NT_SUCCESS(status))
    {
        syscall_failed("NtCreateFile", status);
        DPRINT_ERR("Could check if the file %s exists", filepath);
        return FALSE;
    }
    NtClose(hFile); hFile = NULL;
    return TRUE;
}
