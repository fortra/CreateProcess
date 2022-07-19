#include "main.h"

ULONG CsrAllocateMessagePointer(
    IN OUT PCSR_CAPTURE_BUFFER CaptureBuffer,
    IN ULONG MessageLength,
    OUT PVOID* CapturedData)
{
    if (MessageLength == 0)
    {
        *CapturedData = NULL;
        CapturedData = NULL;
    }
    else
    {
        /* Set the capture data at our current available buffer */
        *CapturedData = CaptureBuffer->BufferEnd;

        /* Align it to a 4-byte boundary */
        MessageLength = (MessageLength + 3) & ~3;

        /* Move our available buffer beyond this space */
        CaptureBuffer->BufferEnd = (PVOID)((ULONG_PTR)CaptureBuffer->BufferEnd + MessageLength);
    }

    /* Write down this pointer in the array and increase the count */
    CaptureBuffer->PointerOffsetsArray[CaptureBuffer->PointerCount++] = (ULONG_PTR)CapturedData;

    /* Return the aligned length */
    return MessageLength;
}

VOID CsrCaptureMessageString(
    IN PCSR_CAPTURE_BUFFER CaptureBuffer,
    IN PCSTR String,
    IN ULONG StringLength,
    IN ULONG MaximumLength,
    OUT PSTRING CapturedString)
{
    /*
     * If we don't have a string, initialize an empty one,
     * otherwise capture the given string.
     */
    if (!String)
    {
        CapturedString->Length = 0;
        CapturedString->MaximumLength = (USHORT)MaximumLength;

        /* Allocate a pointer for it */
        CsrAllocateMessagePointer(CaptureBuffer,
            MaximumLength,
            (PVOID*)&CapturedString->Buffer);
    }
    else
    {
        /* Cut-off the string length if needed */
        if (StringLength > MaximumLength)
            StringLength = MaximumLength;

        CapturedString->Length = (USHORT)StringLength;

        /* Allocate a buffer and get its size */
        CapturedString->MaximumLength =
            (USHORT)CsrAllocateMessagePointer(CaptureBuffer,
                MaximumLength,
                (PVOID*)&CapturedString->Buffer);

        /* If the string has data, copy it into the buffer */
        if (StringLength)
            memcpy(CapturedString->Buffer, String, StringLength);
    }

    /* Null-terminate the string if we don't take up the whole space */
    if (CapturedString->Length < CapturedString->MaximumLength)
        CapturedString->Buffer[CapturedString->Length] = '\0';
}

VOID CsrCaptureMessageUnicodeStringInPlace(
    IN OUT PCSR_CAPTURE_BUFFER CaptureBuffer,
    IN PUNICODE_STRING String)
{
    if (!String)
        return;

    /* This is a way to capture the UNICODE string, since (Maximum)Length are also in bytes */
    CsrCaptureMessageString(CaptureBuffer,
        (PCSTR)String->Buffer,
        String->Length,
        String->MaximumLength,
        (PSTRING)String);

    /* Null-terminate the string */
    if (String->MaximumLength >= String->Length + sizeof(WCHAR))
    {
        String->Buffer[String->Length / sizeof(WCHAR)] = L'\0';
    }
}

/*
 * find a pattern within the code of an API,
 * get the address of a global variable and
 * return its address
 */
PVOID find_generic(
    PVOID funcAddress,
    PBYTE searchPattern,
    ULONG32 patternSize)
{
    ULONG sizeOfRegion = 0x100;

    for (ULONG i = 0; i < sizeOfRegion; i++)
    {
        PVOID address = RVA2VA(PVOID, funcAddress, i);
        if (!memcmp(address, searchPattern, patternSize))
        {
            ULONG32 ripOffset = *RVA2VA(PULONG32, address, patternSize);
            PVOID rip = RVA2VA(PVOID, address, patternSize + sizeof(ULONG32));
            return RVA2VA(PVOID, rip, ripOffset);
        }
    }

    return NULL;
}

/*
 * We need to find the global variable CsrPortMemoryRemoteDelta
 * which is referenced in CsrClientCallServer.
 * This is a bit hacky but it works
 */
BOOL find_csr_port_memory_remote_delta(PULONG_PTR pCsrPortMemoryRemoteDelta)
{
    BYTE search_pattern[] = { 0x4c, 0x8b, 0x0d };
    PVOID address = NULL;

    PVOID addr_CsrClientCallServer = get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        CsrClientCallServer_SW2_HASH,
        0);
    if (!addr_CsrClientCallServer)
    {
        api_not_found("CsrClientCallServer");
        goto cleanup;
    }

    address = find_generic(
        addr_CsrClientCallServer,
        search_pattern,
        sizeof(search_pattern));

    if (address)
    {
        *pCsrPortMemoryRemoteDelta = *(PULONG_PTR)address;
        DPRINT("[i] CsrPortMemoryRemoteDelta: 0x%p\n", (PVOID)*pCsrPortMemoryRemoteDelta);
        return TRUE;
    }

cleanup:
    PRINT_ERR("[!] could not find the CsrPortMemoryRemoteDelta!\n");
    return FALSE;
}

/*
 * We need to find the global variable CsrPortHandle
 * which is referenced in CsrClientCallServer.
 * This is a bit hacky but it works
 */
BOOL find_csr_port_handle(PHANDLE pCsrPortHandle)
{
    BYTE search_pattern[] = { 0x48, 0x8b, 0x0d };
    PVOID address = NULL;

    PVOID addr_CsrClientCallServer = get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        CsrClientCallServer_SW2_HASH,
        0);
    if (!addr_CsrClientCallServer)
    {
        api_not_found("CsrClientCallServer");
        goto cleanup;
    }

    address = find_generic(
        addr_CsrClientCallServer,
        search_pattern,
        sizeof(search_pattern));

    if (address)
    {
        *pCsrPortHandle = *(PHANDLE)address;
        DPRINT("[i] CsrPortHandle: 0x%p\n", *pCsrPortHandle);
        return TRUE;
    }

cleanup:
    PRINT_ERR("[!] could not find the CsrPortHandle!\n");
    return FALSE;
}

/*
 * We need to find the global variable CsrPortBaseTag
 * which is referenced in CsrAllocateCaptureBuffer.
 * This is a bit hacky but it works
 */
BOOL find_csr_port_base_tag(PULONG32 pCsrPortBaseTag)
{
    BYTE search_pattern[] = { 0x8b, 0x15 };
    PVOID address = NULL;

    PVOID addr_CsrAllocateCaptureBuffer = get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        CsrAllocateCaptureBuffer_SW2_HASH,
        0);
    if (!addr_CsrAllocateCaptureBuffer)
    {
        api_not_found("CsrAllocateCaptureBuffer");
        goto cleanup;
    }

    address = find_generic(
        addr_CsrAllocateCaptureBuffer,
        search_pattern,
        sizeof(search_pattern));

    if (address)
    {
        *pCsrPortBaseTag = *(PULONG32)address;
        DPRINT("[i] CsrPortBaseTag: 0x%x\n", *pCsrPortBaseTag);
        return TRUE;
    }

cleanup:
    PRINT_ERR("[!] could not find the CsrPortBaseTag!\n");
    return FALSE;
}

/*
 * We need to find the global variable CsrPortHeap
 * which is referenced in CsrAllocateCaptureBuffer.
 * This is a bit hacky but it works
 */
BOOL find_csr_port_heap(PHANDLE pCsrPortHeap)
{
    BYTE search_pattern[] = { 0x48, 0x8b, 0x0d };
    PVOID address = NULL;

    PVOID addr_CsrAllocateCaptureBuffer = get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        CsrAllocateCaptureBuffer_SW2_HASH,
        0);
    if (!addr_CsrAllocateCaptureBuffer)
    {
        api_not_found("CsrAllocateCaptureBuffer");
        goto cleanup;
    }

    address = find_generic(
        addr_CsrAllocateCaptureBuffer,
        search_pattern,
        sizeof(search_pattern));

    if (address)
    {
        *pCsrPortHeap = *(PHANDLE)address;
        DPRINT("[i] CsrPortHeap: 0x%p\n", *pCsrPortHeap);
        return TRUE;
    }

cleanup:
    PRINT_ERR("[!] could not find the CsrPortHeap!\n");
    return FALSE;
}

BOOL CsrFreeCaptureBuffer(PCSR_CAPTURE_BUFFER captureBuffer)
{
    HANDLE CsrPortHeap = NULL;
    BOOL success = FALSE;

    RtlFreeHeap_t _RtlFreeHeap = get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlFreeHeap_SW2_HASH,
        0);
    if (!_RtlFreeHeap)
    {
        api_not_found("RtlFreeHeap");
        goto cleanup;
    }

    success = find_csr_port_heap(&CsrPortHeap);
    if (!success || !CsrPortHeap)
        return FALSE;

    success = _RtlFreeHeap(CsrPortHeap, 0, captureBuffer);

cleanup:
    return success;
}

PCSR_CAPTURE_BUFFER CsrAllocateCaptureBuffer(ULONG ArgumentCount, ULONG BufferSize)
{
    HANDLE CsrPortHeap = NULL;
    ULONG32 CsrPortBaseTag = 0;
    BOOL success = FALSE;
    PCSR_CAPTURE_BUFFER CaptureBuffer = NULL;
    ULONG OffsetsArraySize = 0;
    RtlAllocateHeap_t _RtlAllocateHeap = NULL;

    _RtlAllocateHeap = (RtlAllocateHeap_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlAllocateHeap_SW2_HASH,
        0);
    if (!_RtlAllocateHeap)
    {
        api_not_found("RtlAllocateHeap");
        goto cleanup;
    }

    success = find_csr_port_heap(&CsrPortHeap);
    if (!success || !CsrPortHeap)
        goto cleanup;

    success = find_csr_port_base_tag(&CsrPortBaseTag);
    if (!success)
        goto cleanup;

    OffsetsArraySize = ArgumentCount * sizeof(ULONG_PTR);

    /* Add the size of the header and of the pointer-offset array */
    BufferSize += FIELD_OFFSET(CSR_CAPTURE_BUFFER, PointerOffsetsArray) +
        OffsetsArraySize;

    /* Add the size of the alignment padding for each argument */
    BufferSize += ArgumentCount * 3;

    /* Align it to a 4-byte boundary */
    BufferSize = (BufferSize + 3) & ~3;

    CaptureBuffer = (PCSR_CAPTURE_BUFFER)_RtlAllocateHeap(CsrPortHeap, CsrPortBaseTag, BufferSize);
    if (!CaptureBuffer)
        goto cleanup;

    /* Initialize the header */
    CaptureBuffer->Size = BufferSize;
    CaptureBuffer->PointerCount = 0;

    /* Initialize the pointer-offset array */
    memset(CaptureBuffer->PointerOffsetsArray, 0, OffsetsArraySize);

    /* Point to the start of the free buffer */
    CaptureBuffer->BufferEnd = (PVOID)((ULONG_PTR)CaptureBuffer->PointerOffsetsArray +
        OffsetsArraySize);

cleanup:
    /* Return the address of the buffer */
    return CaptureBuffer;
}

NTSTATUS CsrCaptureMessageMultiUnicodeStringsInPlace(
    OUT PCSR_CAPTURE_BUFFER* pCaptureBuffer,
    IN ULONG StringsCount,
    IN PUNICODE_STRING* MessageStrings)
{
    ULONG Count = 0;
    ULONG Size = 0;

    /* Compute the required size for the capture buffer */
    Count = 0;
    while (Count < StringsCount)
    {
        if (MessageStrings[Count])
            Size += MessageStrings[Count]->MaximumLength;

        ++Count;
    }

    *pCaptureBuffer = CsrAllocateCaptureBuffer(StringsCount, Size);
    if (!*pCaptureBuffer)
        return STATUS_NO_MEMORY;


    /* Now capture each UNICODE string */
    Count = 0;
    while (Count < StringsCount)
    {
        if (MessageStrings[Count])
            CsrCaptureMessageUnicodeStringInPlace(*pCaptureBuffer, MessageStrings[Count]);

        ++Count;
    }

    return STATUS_SUCCESS;
}

/*
 * Register the new process to the CSRSS using syscalls for extra sneakyness
 */
NTSTATUS CsrClientCallServer(
    IN PBASE_API_MSG ApiMessage,
    IN PCSR_CAPTURE_BUFFER CaptureBuffer,
    IN ULONG ApiNumber,
    IN ULONG DataLength)
{
    HANDLE CsrPortHandle = NULL;
    ULONG_PTR CsrPortMemoryRemoteDelta = 0;
    ULONG PointerCount = 0;
    PULONG_PTR OffsetPointer = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    SIZE_T BufferLength = 0x3b8;
    BOOL success = FALSE;

    success = find_csr_port_handle(&CsrPortHandle);
    if (!success || !CsrPortHandle)
        goto cleanup;
    success = find_csr_port_memory_remote_delta(&CsrPortMemoryRemoteDelta);
    if (!success || !CsrPortMemoryRemoteDelta)
        goto cleanup;

    /* Fill out the Port Message Header */
    ApiMessage->PortHeader.Header.u1.s1.DataLength = DataLength + 0x18;
    ApiMessage->PortHeader.Header.u1.s1.TotalLength = DataLength + 0x40;
    ApiMessage->PortHeader.ApiNumber = ApiNumber;
    ApiMessage->PortHeader.CaptureBuffer = NULL;

    if (CaptureBuffer)
    {
        /*
         * We have to convert from our local (client) view
         * to the remote (server) view.
         */
        ApiMessage->PortHeader.CaptureBuffer = (PCSR_CAPTURE_HEADER)
            ((ULONG_PTR)CaptureBuffer + CsrPortMemoryRemoteDelta);

        /* Lock the buffer */
        CaptureBuffer->BufferEnd = NULL;

        /*
         * Each client pointer inside the CSR message is converted into
         * a server pointer, and each pointer to these message pointers
         * is converted into an offset.
         */
        PointerCount = CaptureBuffer->PointerCount;
        OffsetPointer = CaptureBuffer->PointerOffsetsArray;
        while (PointerCount--)
        {
            if (*OffsetPointer != 0)
            {
                *(PULONG_PTR)*OffsetPointer += CsrPortMemoryRemoteDelta;
                *OffsetPointer -= (ULONG_PTR)ApiMessage;
            }
            ++OffsetPointer;
        }
    }

    // trigger the syscall :)
    status = _NtAlpcSendWaitReceivePort(
        CsrPortHandle,
        0x20000,
        ApiMessage,
        NULL,
        ApiMessage,
        &BufferLength,
        NULL,
        NULL);

    if (CaptureBuffer)
    {
        /*
         * We have to convert back from the remote (server) view
         * to our local (client) view.
         */
        ApiMessage->PortHeader.CaptureBuffer = (PCSR_CAPTURE_HEADER)
            ((ULONG_PTR)ApiMessage->PortHeader.CaptureBuffer - CsrPortMemoryRemoteDelta);

        /*
         * Convert back the offsets into pointers to CSR message
         * pointers, and convert back these message server pointers
         * into client pointers.
         */
        PointerCount = CaptureBuffer->PointerCount;
        OffsetPointer = CaptureBuffer->PointerOffsetsArray;
        while (PointerCount--)
        {
            if (*OffsetPointer != 0)
            {
                *OffsetPointer += (ULONG_PTR)ApiMessage;
                *(PULONG_PTR)*OffsetPointer -= CsrPortMemoryRemoteDelta;
            }
            ++OffsetPointer;
        }
    }

cleanup:
    return status;
}

NTSTATUS register_with_csr(
    IN PPROCESS_INFORMATION pi,
    IN PPS_CREATE_INFO ci,
    IN LPCWSTR process_image,
    IN LPCWSTR nt_process_image)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PCSR_CAPTURE_BUFFER captureBuffer = NULL;
    BASE_API_MSG m = { 0 };
    PUNICODE_STRING stringToCapture[4] = { 0 };
    BYTE locale[0x14] = { 0 };
    RtlInitUnicodeString_t _RtlInitUnicodeString = NULL;

    _RtlInitUnicodeString = (RtlInitUnicodeString_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlInitUnicodeString_SW2_HASH,
        0);
    if (!_RtlInitUnicodeString)
    {
        api_not_found("RtlInitUnicodeString");
        goto cleanup;
    }

    // build msg for csr

    memset(&m, 0, sizeof(BASE_API_MSG));

    // basic fields
    m.CreateProcessMSG.ProcessHandle = (HANDLE)((ULONG_PTR)pi->hProcess | 2);
    m.CreateProcessMSG.ThreadHandle = pi->hThread;
    m.CreateProcessMSG.ClientId.UniqueProcess = (HANDLE)(ULONG_PTR)pi->dwProcessId;
    m.CreateProcessMSG.ClientId.UniqueThread = (HANDLE)(ULONG_PTR)pi->dwThreadId;
    m.CreateProcessMSG.CreationFlags = 0x0;
    m.CreateProcessMSG.PebAddressNative = (ULONG64)ci->SuccessState.PebAddressNative;
    m.CreateProcessMSG.PebAddressWow64 = 0x0;
#ifdef _WIN64
    m.CreateProcessMSG.ProcessorArchitecture = 9;
#else
    m.CreateProcessMSG.ProcessorArchitecture = 0;
#endif

    // sxs
    m.CreateProcessMSG.Sxs.Flags = 0x40;
    m.CreateProcessMSG.Sxs.ProcessParameterFlags = 0x6001;
    m.CreateProcessMSG.Sxs.FileHandle = ci->SuccessState.FileHandle;
    _RtlInitUnicodeString(&m.CreateProcessMSG.Sxs.SxsWin32ExePath, process_image);
    _RtlInitUnicodeString(&m.CreateProcessMSG.Sxs.SxsNtExePath, nt_process_image);
    m.CreateProcessMSG.Sxs.PolicyStream.ManifestAddress = ci->SuccessState.ManifestAddress;
    m.CreateProcessMSG.Sxs.PolicyStream.ManifestSize = ci->SuccessState.ManifestSize;
    m.CreateProcessMSG.Sxs.FileName3.Length = 0x14;
    m.CreateProcessMSG.Sxs.FileName3.MaximumLength = 0x14;
    m.CreateProcessMSG.Sxs.FileName3.Buffer = (PWCH)locale;
    memcpy(m.CreateProcessMSG.Sxs.FileName3.Buffer, "\x65\x00\x6e\x00\x2d\x00\x55\x00\x53\x00\x00\x00\x65\x00\x6e\x00\x00\x00\x00\x00", 0x14); // wtf windows
    _RtlInitUnicodeString(&m.CreateProcessMSG.Sxs.FileName4, L"-----------------------------------------------------------");

    // notify the windows subsystem

    stringToCapture[0] = &m.CreateProcessMSG.Sxs.SxsWin32ExePath;
    stringToCapture[1] = &m.CreateProcessMSG.Sxs.SxsNtExePath;
    stringToCapture[2] = &m.CreateProcessMSG.Sxs.FileName3;
    stringToCapture[3] = &m.CreateProcessMSG.Sxs.FileName4;

    // here we could simply call ntdll!CsrCaptureMessageMultiUnicodeStringsInPlace
    status = CsrCaptureMessageMultiUnicodeStringsInPlace(&captureBuffer, 4, stringToCapture);

    if (!NT_SUCCESS(status))
    {
        PRINT_ERR("[-] CsrCaptureMessageMultiUnicodeStringsInPlace failed, status: 0x%lx\n", status);
        goto cleanup;
    }
    DPRINT("[+] Got the capture buffer = 0x%p\n", captureBuffer);

    // here we could simply call ntdll!CsrClientCallServer
    status = CsrClientCallServer(
        &m,
        captureBuffer,
        CSR_MAKE_API_NUMBER(BASESRV_SERVERDLL_INDEX, BasepRegisterThread),
        sizeof(BASE_API_MSG) - sizeof(PORT_MESSAGE));

    if (!NT_SUCCESS(status))
    {
        PRINT_ERR("[-] CsrClientCallServer failed, status: 0x%lx\n", status);
        goto cleanup;
    }

    PRINT("[+] Registered new process with the CSRSS\n");

cleanup:
    if (captureBuffer)
    {
        // here we could simply call ntdll!CsrFreeCaptureBuffer
        CsrFreeCaptureBuffer(captureBuffer);
    }

    return status;
}

HANDLE get_parent_handle(
    IN DWORD ppid)
{
    HANDLE hProcess = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    OBJECT_ATTRIBUTES obj_attributes = { 0 };
    CLIENT_ID client_id = { 0 };

    if (!ppid)
    {
        hProcess = NtCurrentProcess();
        goto cleanup;
    }

    InitializeObjectAttributes(
        &obj_attributes,
        NULL,
        0,
        NULL,
        NULL);

    client_id.UniqueProcess = (HANDLE)(ULONG_PTR)ppid;

    status = _NtOpenProcess(
        &hProcess,
        PROCESS_CREATE_PROCESS,
        &obj_attributes,
        &client_id);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERR("[-] NtOpenProcess failed, status: 0x%lx\n", status);
        hProcess = NtCurrentProcess();
        goto cleanup;
    }

    PRINT("[i] Parent process\n");
    PRINT("[i]      PPID = %ld\n", ppid);
    PRINT("[i] hPprocess = 0x%p\n", hProcess);

cleanup:
    return hProcess;
}

PVOID get_peb_address(
    IN HANDLE hProcess)
{
    PROCESS_BASIC_INFORMATION basic_info = { 0 };
    basic_info.PebBaseAddress = 0;
    PROCESSINFOCLASS ProcessInformationClass = 0;
    NTSTATUS status = _NtQueryInformationProcess(
        hProcess,
        ProcessInformationClass,
        &basic_info,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL);
    if (!NT_SUCCESS(status))
    {
        PRINT("[-] Failed to call NtQueryInformationProcess, status: 0x%lx\n", status);
        return 0;
    }

    return basic_info.PebBaseAddress;
}

DWORD get_rva_entrypoint(
    PIMAGE_DOS_HEADER dos)
{
    PIMAGE_NT_HEADERS nt = NULL;
    DWORD rva_entrypoint = 0;

    // check the MZ magic bytes
    if (dos->e_magic != 0x5A4D)
    {
        printf("[-] invalid magic bytes\n");
        goto cleanup;
    }

    nt = RVA(PIMAGE_NT_HEADERS, dos, dos->e_lfanew);

    // check the NT_HEADER signature
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        goto cleanup;

    rva_entrypoint = nt->OptionalHeader.AddressOfEntryPoint;

cleanup:
    return rva_entrypoint;
}

PVOID get_entrypoint_address(
    IN HANDLE hProcess,
    IN PVOID image_base_address,
    IN PIMAGE_DOS_HEADER dos)
{
    DWORD rva_entrypoint_addr = 0;
    PVOID entrypoint_addr = NULL;

    rva_entrypoint_addr = get_rva_entrypoint(dos);
    if (!rva_entrypoint_addr)
    {
        PRINT("[-] Failed to get the address of the entry point\n");
        goto cleanup;
    }

    entrypoint_addr = RVA2VA(PVOID, image_base_address, rva_entrypoint_addr);

cleanup:
    return entrypoint_addr;
}

PVOID get_image_base_address(
    IN HANDLE hProcess,
    IN PVOID peb_address,
    IN BOOL is_x64)
{
    PVOID read_addr = NULL;
    SIZE_T buffer_size = 0;
    PVOID image_base_address = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (is_x64)
    {
        // is x64
        read_addr = RVA2VA(PVOID, peb_address, 0x10);
        buffer_size = 8;
    }
    else
    {
        // is x86
        read_addr = RVA2VA(PVOID, peb_address, 0x08);
        buffer_size = 4;
    }

    status = _NtReadVirtualMemory(
        hProcess,
        read_addr,
        &image_base_address,
        buffer_size,
        NULL);
    if (!NT_SUCCESS(status))
    {
        PRINT("[-] Failed to call NtReadVirtualMemory, status: 0x%lx\n", status);
        return NULL;
    }

    return image_base_address;
}

VOID find_manifest(
    IN HANDLE hProcess,
    IN PVOID image_base_address,
    IN PIMAGE_DOS_HEADER dos,
    IN BOOL is_x64,
    OUT PVOID* manifest_address,
    OUT PDWORD manifest_size)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PIMAGE_NT_HEADERS nt = NULL;
    PIMAGE_SECTION_HEADER sec = NULL;
    PVOID resource_section_address = NULL;
    SIZE_T resource_section_size = 0;
    PVOID resource_section = NULL;
    *manifest_address = NULL;
    *manifest_size = 0;

    nt = RVA(PIMAGE_NT_HEADERS, dos, dos->e_lfanew);

    // check the NT_HEADER signature
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        goto cleanup;

    if (is_x64)
    {
        sec = RVA2VA(PIMAGE_SECTION_HEADER, &nt->OptionalHeader, 0xf0);
    }
    else
    {
        sec = RVA2VA(PIMAGE_SECTION_HEADER, &nt->OptionalHeader, 0xe0);
    }

    while (TRUE)
    {
        if (!sec->VirtualAddress)
        {
            //PRINT("[-] Could not find the .rsrc section\n");
            goto cleanup;
        }

        if (!strncmp((LPCSTR)sec->Name, ".rsrc", 6))
        {
            resource_section_address = RVA2VA(PVOID, image_base_address, sec->VirtualAddress);
            resource_section_size = sec->SizeOfRawData;
            //PRINT("found the .rsrc section at: 0x%p (0x%lx)\n", resource_section_address, resource_section_size);
            break;
        }
        sec = RVA2VA(PIMAGE_SECTION_HEADER, sec, sizeof(IMAGE_SECTION_HEADER));
    }

    resource_section = calloc(resource_section_size, 1);

    status = _NtReadVirtualMemory(
        hProcess,
        resource_section_address,
        resource_section,
        resource_section_size,
        NULL);
    if (!NT_SUCCESS(status))
    {
        PRINT("[-] Failed to call NtReadVirtualMemory, status: 0x%lx\n", status);
        goto cleanup;
    }

    // look for the XML document inside the .rsrc section

    SIZE_T index = 0;
    PVOID ptr = NULL;
    while (index < resource_section_size)
    {
        ptr = RVA2VA(PVOID, resource_section, index);
        if (!strncmp(ptr, "<?xml", 5))
        {
            *manifest_address = RVA2VA(PVOID, resource_section_address, index);
            *manifest_size = strnlen(ptr, resource_section_size - index);
            //PRINT("found the manifest address: 0x%p\n", *manifest_address);
            //PRINT("found the manifest size:%d\n", *manifest_size);
            break;
        }
        // increment the ptr address by one
        index++;
    }

cleanup:
    if (resource_section)
        free(resource_section);
}

BOOL set_parameters_and_directory(
    IN HANDLE hProcess,
    IN PVOID peb_address,
    IN LPWSTR process_image,
    IN LPWSTR nt_process_image,
    IN LPWSTR wparams,
    IN LPWSTR wdirectory,
    IN BOOL is_x64)
{
    BOOL ret_val = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING ustr_process_parameters = { 0 };
    UNICODE_STRING ustr_current_directory = { 0 };
    UNICODE_STRING ustr_process_image = { 0 };
    WCHAR process_parameters[MAX_PATH] = { 0 };
    PMY_RTL_USER_PROCESS_PARAMETERS pProcParams = NULL;
    RtlCreateProcessParametersEx_t _RtlCreateProcessParametersEx = NULL;
    RtlDestroyProcessParameters_t _RtlDestroyProcessParameters = NULL;
    RtlInitUnicodeString_t _RtlInitUnicodeString = NULL;
    PVOID params_remote_address = NULL;
    PVOID ptr_to_params = NULL;
    SIZE_T region_size = 0;
    ULONG_PTR params_address_diff = 0;

    _RtlInitUnicodeString = (RtlInitUnicodeString_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlInitUnicodeString_SW2_HASH,
        0);
    if (!_RtlInitUnicodeString)
    {
        api_not_found("RtlInitUnicodeString");
        goto cleanup;
    }
    _RtlCreateProcessParametersEx = (RtlCreateProcessParametersEx_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlCreateProcessParametersEx_SW2_HASH,
        0);
    if (!_RtlCreateProcessParametersEx)
    {
        api_not_found("RtlCreateProcessParametersEx");
        goto cleanup;
    }
    _RtlDestroyProcessParameters = (RtlDestroyProcessParameters_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlDestroyProcessParameters_SW2_HASH,
        0);
    if (!_RtlDestroyProcessParameters)
    {
        api_not_found("RtlDestroyProcessParameters");
        goto cleanup;
    }

    _RtlInitUnicodeString(&ustr_process_image, nt_process_image);

    if (wparams)
    {
        swprintf_s(process_parameters, MAX_PATH, L"\"%ws\" %ws", process_image, wparams);
    }
    else
    {
        swprintf_s(process_parameters, MAX_PATH, L"\"%ws\"", process_image);
    }
    _RtlInitUnicodeString(&ustr_process_parameters, process_parameters);

    if (wdirectory)
    {
        _RtlInitUnicodeString(&ustr_current_directory, wdirectory);
    }

    /*
     * the RTL_USER_PROCESS_PARAMETERS structure is quite large
     * and changes from version to version,
     * that is why I preffer using this API
     */
    status = _RtlCreateProcessParametersEx(
        (PRTL_USER_PROCESS_PARAMETERS*)&pProcParams,
        &ustr_process_image,
        NULL,
        wdirectory ? &ustr_current_directory : NULL,
        &ustr_process_parameters,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        RTL_USER_PROC_PARAMS_NORMALIZED);

    if (!NT_SUCCESS(status))
    {
        PRINT_ERR("[-] RtlCreateProcessParametersEx failed, status: 0x%lx\n", status);
        goto cleanup;
    }

    region_size  = pProcParams->EnvironmentSize + pProcParams->MaximumLength;
    status = _NtAllocateVirtualMemory(
        hProcess,
        &params_remote_address,
        0,
        &region_size,
        MEM_COMMIT,
        PAGE_READWRITE);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERR("[-] NtAllocateVirtualMemory failed, status: 0x%lx\n", status);
        goto cleanup;
    }

    // we need to adjust all the pointers so that they make sense on the remote process

    params_address_diff = (ULONG_PTR)params_remote_address - (ULONG_PTR)pProcParams;

    if (pProcParams->CurrentDirectory.DosPath.Buffer)
        pProcParams->CurrentDirectory.DosPath.Buffer = RVA2VA(PVOID, pProcParams->CurrentDirectory.DosPath.Buffer, params_address_diff);
    if (pProcParams->DllPath.Buffer)
        pProcParams->DllPath.Buffer = RVA2VA(PVOID, pProcParams->DllPath.Buffer, params_address_diff);
    if (pProcParams->ImagePathName.Buffer)
        pProcParams->ImagePathName.Buffer = RVA2VA(PVOID, pProcParams->ImagePathName.Buffer, params_address_diff);
    if (pProcParams->CommandLine.Buffer)
        pProcParams->CommandLine.Buffer = RVA2VA(PVOID, pProcParams->CommandLine.Buffer, params_address_diff);
    if (pProcParams->Environment)
        pProcParams->Environment = RVA2VA(PVOID, pProcParams->Environment, params_address_diff);
    if (pProcParams->WindowTitle.Buffer)
        pProcParams->WindowTitle.Buffer = RVA2VA(PVOID, pProcParams->WindowTitle.Buffer, params_address_diff);
    if (pProcParams->DesktopInfo.Buffer)
        pProcParams->DesktopInfo.Buffer = RVA2VA(PVOID, pProcParams->DesktopInfo.Buffer, params_address_diff);
    if (pProcParams->ShellInfo.Buffer)
        pProcParams->ShellInfo.Buffer = RVA2VA(PVOID, pProcParams->ShellInfo.Buffer, params_address_diff);
    if (pProcParams->RuntimeData.Buffer)
        pProcParams->RuntimeData.Buffer = RVA2VA(PVOID, pProcParams->RuntimeData.Buffer, params_address_diff);
    if (pProcParams->PackageDependencyData)
        pProcParams->PackageDependencyData = RVA2VA(PVOID, pProcParams->PackageDependencyData, params_address_diff);
    if (pProcParams->RedirectionDllName.Buffer)
        pProcParams->RedirectionDllName.Buffer = RVA2VA(PVOID, pProcParams->RedirectionDllName.Buffer, params_address_diff);
    if (pProcParams->HeapPartitionName.Buffer)
        pProcParams->HeapPartitionName.Buffer = RVA2VA(PVOID, pProcParams->HeapPartitionName.Buffer, params_address_diff);

    region_size  = pProcParams->EnvironmentSize + pProcParams->MaximumLength;
    status = _NtWriteVirtualMemory(
        hProcess,
        params_remote_address,
        pProcParams,
        region_size,
        NULL);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERR("[-] NtWriteVirtualMemory failed, status: 0x%lx\n", status);
        goto cleanup;
    }

    if (is_x64)
    {
        ptr_to_params = RVA2VA(PVOID, peb_address, 0x20);
        region_size = 8;
    }
    else
    {
        ptr_to_params = RVA2VA(PVOID, peb_address, 0x10);
        region_size = 4;
    }

    status = _NtWriteVirtualMemory(
        hProcess,
        ptr_to_params,
        &params_remote_address,
        region_size,
        NULL);
    if (!NT_SUCCESS(status))
    {
        PRINT_ERR("[-] NtWriteVirtualMemory failed, status: 0x%lx\n", status);
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    if (pProcParams)
        _RtlDestroyProcessParameters((PRTL_USER_PROCESS_PARAMETERS)pProcParams);

    return ret_val;
}

DWORD get_pid(
    IN HANDLE hProcess)
{
    PROCESS_BASIC_INFORMATION basic_info;
    basic_info.UniqueProcessId = 0;
    PROCESSINFOCLASS ProcessInformationClass = 0;
    NTSTATUS status = _NtQueryInformationProcess(
        hProcess,
        ProcessInformationClass,
        &basic_info,
        sizeof(PROCESS_BASIC_INFORMATION),
        NULL);
    if (!NT_SUCCESS(status))
    {
        PRINT("[-] Failed to call NtQueryInformationProcess, status: 0x%lx\n", status);
        return 0;
    }

    return basic_info.UniqueProcessId;
}

DWORD get_tid(
    IN HANDLE hThread)
{
    THREAD_BASIC_INFORMATION basic_info = { 0 };
    THREADINFOCLASS ProcessInformationClass = 0;

    NTSTATUS status = _NtQueryInformationThread(
        hThread,
        ProcessInformationClass,
        &basic_info,
        sizeof(THREAD_BASIC_INFORMATION),
        NULL);
    if (!NT_SUCCESS(status))
    {
        PRINT("[-] Failed to call NtQueryInformationThread, status: 0x%lx\n", status);
        return 0;
    }

    return (DWORD)(ULONG_PTR)basic_info.ClientId.UniqueThread;
}

BOOL get_arch(
    IN PIMAGE_DOS_HEADER dos,
    OUT PBOOL is_x64)
{
    BOOL ret_val = FALSE;
    PIMAGE_NT_HEADERS nt = NULL;

    // check the MZ magic bytes
    if (dos->e_magic != 0x5A4D)
    {
        goto cleanup;
    }

    nt = RVA(PIMAGE_NT_HEADERS, dos, dos->e_lfanew);

    // check the NT_HEADER signature
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        goto cleanup;

    if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        *is_x64 = TRUE;
    }
    else if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        *is_x64 = FALSE;
    }
    else
    {
        // unknown Magic
        goto cleanup;
    }

    ret_val = TRUE;

cleanup:
    return ret_val;
}

BOOL create_process_with_ntcreateprocex(
    OUT PPROCESS_INFORMATION pi,
    OUT PPS_CREATE_INFO ci,
    IN LPWSTR process_image,
    IN LPWSTR nt_process_image,
    IN LPWSTR wparams,
    IN LPWSTR wdirectory,
    IN DWORD ppid,
    IN BOOL block_dlls)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOL success = FALSE;
    BOOL ret_val = FALSE;
    HANDLE hFile = NULL;
    HANDLE hSection = NULL;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    HANDLE hPprocess = NULL;
    OBJECT_ATTRIBUTES obj_attributes = { 0 };
    UNICODE_STRING ustr_process_path = { 0 };
    IO_STATUS_BLOCK io_status_block = { 0 };
    PVOID entrypoint_addr = NULL;
    PVOID peb_address = NULL;
    PVOID manifest_address = NULL;
    DWORD manifest_size = 0;
    PIMAGE_DOS_HEADER dos = NULL;
    PVOID image_base_address = NULL;
    BOOL is_x64 = TRUE;

    dos = calloc(DOS_HEADERS_SIZE, 1);
    if (!dos)
    {
        PRINT("[-] Calloc failed\n");
        goto cleanup;
    }

    ustr_process_path.Buffer = nt_process_image;
    ustr_process_path.Length = wcsnlen(ustr_process_path.Buffer, MAX_PATH);
    ustr_process_path.Length *= 2;
    ustr_process_path.MaximumLength = ustr_process_path.Length + 2;

    InitializeObjectAttributes(
        &obj_attributes,
        &ustr_process_path,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    // open handle to the file

    status = _NtOpenFile(
        &hFile,
        FILE_READ_DATA|FILE_EXECUTE|FILE_READ_ATTRIBUTES|SYNCHRONIZE,
        &obj_attributes,
        &io_status_block,
        FILE_SHARE_READ|FILE_SHARE_DELETE,
        FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(status))
    {
        PRINT("[-] Failed to call NtOpenFile, status: 0x%lx\n", status);
        goto cleanup;
    }

    // read the PE headers

    status = _NtReadFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &io_status_block,
        dos,
        DOS_HEADERS_SIZE,
        NULL,
        NULL);
    if (!NT_SUCCESS(status))
    {
        PRINT("[-] Failed to call NtReadFile, status: 0x%lx\n", status);
        goto cleanup;
    }

    success = get_arch(
        dos,
        &is_x64);
    if (!success)
    {
        PRINT("[-] The file does not seem to be a PE\n");
        goto cleanup;
    }

    if (!is_x64)
    {
        PRINT("[-] Only x64 is supported\n");
        goto cleanup;
    }

    // create section

    status = _NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hFile);
    if (!NT_SUCCESS(status))
    {
        PRINT("[-] Failed to call NtCreateSection, status: 0x%lx\n", status);
        goto cleanup;
    }

    // get a handle to the parent process

    hPprocess = get_parent_handle(ppid);

    // create the process

    status = _NtCreateProcessEx(
        &hProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        hPprocess,
        CREATE_SUSPENDED,
        hSection,
        NULL,
        NULL,
        0);
    if (!NT_SUCCESS(status))
    {
        PRINT("[-] Failed to call NtCreateProcessEx, status: 0x%lx\n", status);
        goto cleanup;
    }

    peb_address = get_peb_address(hProcess);
    if (!peb_address)
    {
        PRINT("[-] Could not find the address of the PEB\n");
        goto cleanup;
    }

    image_base_address = get_image_base_address(
        hProcess,
        peb_address,
        is_x64);
    if (!image_base_address)
    {
        PRINT("[-] Could not find the address of the image base\n");
        goto cleanup;
    }

    entrypoint_addr = get_entrypoint_address(
        hProcess,
        image_base_address,
        dos);
    if (!entrypoint_addr)
    {
        PRINT("[-] Could not find the address of the entry point\n");
        goto cleanup;
    }

    success = set_parameters_and_directory(
        hProcess,
        peb_address,
        process_image,
        nt_process_image,
        wparams,
        wdirectory,
        is_x64);
    if (!success)
    {
        PRINT("[-] Could not set the parameters and directory\n");
        goto cleanup;
    }

    /*
    if (block_dlls)
    {
        DWORD64 policy = 0x100000008;

        status = _NtSetInformationProcess(
            hProcess,
            ProcessMitigationPolicy,
            &policy,
            8);
        if (!NT_SUCCESS(status))
        {
            PRINT("[-] Failed to call NtSetInformationProcess, status: 0x%lx\n", status);
            goto cleanup;
        }
    }
    */

    // creating the thread will trigger the kernel-based process creation notification
    status = _NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        entrypoint_addr,
        NULL,
        THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
        0,
        0,
        0,
        NULL);
    if (!NT_SUCCESS(status))
    {
        PRINT("[-] Failed to call NtCreateThreadEx, status: 0x%lx\n", status);
        goto cleanup;
    }

    find_manifest(
        hProcess,
        image_base_address,
        dos,
        is_x64,
        &manifest_address,
        &manifest_size);

    pi->hProcess = hProcess;
    pi->hThread = hThread;
    pi->dwProcessId = get_pid(hProcess);
    pi->dwThreadId = get_tid(hThread);
    ci->SuccessState.PebAddressNative = (ULONG_PTR)peb_address;
    ci->SuccessState.FileHandle = hFile;
    ci->SuccessState.ManifestAddress = (ULONG_PTR)manifest_address;
    ci->SuccessState.ManifestSize = manifest_size;

    ret_val = TRUE;

cleanup:
    if (hSection)
        _NtClose(hSection);
    if (hPprocess)
        _NtClose(hPprocess);
    if (dos)
        free(dos);

    return ret_val;
}

BOOL create_process_with_ntcreateuserproc(
    OUT PPROCESS_INFORMATION pi,
    OUT PPS_CREATE_INFO ci,
    IN LPWSTR process_image,
    IN LPWSTR nt_process_image,
    IN LPWSTR wparams,
    IN LPWSTR wdirectory,
    IN DWORD ppid,
    IN BOOL block_dlls)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PS_ATTRIBUTE_LIST attrList = { 0 };
    CLIENT_ID clientId = { 0 };
    BOOL ret_val = FALSE;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    ULONG THREAD_FLAGS = 0;
    ULONG PROCESS_FLAGS = 0;
    UNICODE_STRING ustr_process_image = { 0 };
    WCHAR process_parameters[MAX_PATH] = { 0 };
    UNICODE_STRING ustr_process_parameters = { 0 };
    UNICODE_STRING ustr_current_directory = { 0 };
    RtlInitUnicodeString_t _RtlInitUnicodeString = NULL;
    RtlCreateProcessParametersEx_t _RtlCreateProcessParametersEx = NULL;
    RtlDestroyProcessParameters_t _RtlDestroyProcessParameters = NULL;
    PRTL_USER_PROCESS_PARAMETERS pProcParams = NULL;
    HANDLE hPprocess = NULL;
    DWORD64 policy = 0;

    _RtlInitUnicodeString = (RtlInitUnicodeString_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlInitUnicodeString_SW2_HASH,
        0);
    if (!_RtlInitUnicodeString)
    {
        api_not_found("RtlInitUnicodeString");
        goto cleanup;
    }
    _RtlCreateProcessParametersEx = (RtlCreateProcessParametersEx_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlCreateProcessParametersEx_SW2_HASH,
        0);
    if (!_RtlCreateProcessParametersEx)
    {
        api_not_found("RtlCreateProcessParametersEx");
        goto cleanup;
    }
    _RtlDestroyProcessParameters = (RtlDestroyProcessParameters_t)(ULONG_PTR)get_function_address(
        get_library_address(NTDLL_DLL, TRUE),
        RtlDestroyProcessParameters_SW2_HASH,
        0);
    if (!_RtlDestroyProcessParameters)
    {
        api_not_found("RtlDestroyProcessParameters");
        goto cleanup;
    }

    _RtlInitUnicodeString(&ustr_process_image, nt_process_image);

    if (wparams)
    {
        swprintf_s(process_parameters, MAX_PATH, L"\"%ws\" %ws", process_image, wparams);
    }
    else
    {
        swprintf_s(process_parameters, MAX_PATH, L"\"%ws\"", process_image);
    }
    _RtlInitUnicodeString(&ustr_process_parameters, process_parameters);

    if (wdirectory)
    {
        _RtlInitUnicodeString(&ustr_current_directory, wdirectory);
    }

    /*
     * the RTL_USER_PROCESS_PARAMETERS structure is quite large
     * and changes from version to version,
     * that is why I preffer using this API
     */
    status = _RtlCreateProcessParametersEx(
        &pProcParams,
        &ustr_process_image,
        NULL,
        wdirectory ? &ustr_current_directory : NULL,
        &ustr_process_parameters,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        RTL_USER_PROC_PARAMS_NORMALIZED);

    if (!NT_SUCCESS(status))
    {
        PRINT_ERR("[-] RtlCreateProcessParametersEx failed, status: 0x%lx\n", status);
        goto cleanup;
    }

    // set create info
    ci->State = PsCreateInitialState;
    ci->Size = sizeof(PS_CREATE_INFO);
    ci->InitState.InitFlags = WriteOutputOnExit | DetectManifest | 0x20000000;
    ci->InitState.AdditionalFileAccess = FILE_READ_ATTRIBUTES | FILE_READ_DATA;

    // set attribute list
    attrList.TotalLength = sizeof(PS_ATTRIBUTE_LIST);

    attrList.Attributes[0].Attribute = PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE);
    attrList.Attributes[0].Size = ustr_process_image.Length;
    attrList.Attributes[0].ValuePtr = ustr_process_image.Buffer;

    attrList.Attributes[1].Attribute = PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE);
    attrList.Attributes[1].Size = sizeof(CLIENT_ID);
    attrList.Attributes[1].ValuePtr = &clientId;

    hPprocess = get_parent_handle(ppid);
    attrList.Attributes[2].Attribute = PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE);
    attrList.Attributes[2].Size = sizeof(HANDLE);
    attrList.Attributes[2].Value = (ULONG_PTR)hPprocess;

    attrList.Attributes[3].Attribute = PsAttributeValue(PsAttributeChpe, FALSE, TRUE, TRUE);
    attrList.Attributes[3].Size = 1;
    attrList.Attributes[3].Value = 1;

    if (block_dlls)
        policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    attrList.Attributes[4].Attribute = PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE);
    attrList.Attributes[4].Size = sizeof(DWORD64);
    attrList.Attributes[4].Value = (ULONG_PTR)&policy;

    THREAD_FLAGS = THREAD_CREATE_FLAGS_CREATE_SUSPENDED;
    PROCESS_FLAGS = PROCESS_CREATE_FLAGS_SUSPENDED;

    status = _NtCreateUserProcess(
        &hProcess,
        &hThread,
        MAXIMUM_ALLOWED,
        MAXIMUM_ALLOWED,
        NULL,
        NULL,
        PROCESS_FLAGS,
        THREAD_FLAGS,
        pProcParams,
        ci,
        &attrList);

    if (!NT_SUCCESS(status))
    {
        PRINT("[-] Failed to call NtCreateUserProcess, status: 0x%lx\n", status);
        goto cleanup;
    }

    pi->hProcess    = hProcess;
    pi->hThread     = hThread;
    pi->dwProcessId = (DWORD)(ULONG_PTR)clientId.UniqueProcess;
    pi->dwThreadId  = (DWORD)(ULONG_PTR)clientId.UniqueThread;

    ret_val = TRUE;

cleanup:
    if (pProcParams)
        _RtlDestroyProcessParameters(pProcParams);
    if (hPprocess)
        _NtClose(hPprocess);

    return ret_val;
}

BOOL create_process_internal(
    OUT PPROCESS_INFORMATION pi,
    IN BOOL use_ntcreateuserproc,
    IN LPWSTR process_image,
    IN LPWSTR wparams,
    IN LPWSTR wdirectory,
    IN BOOL suspended,
    IN DWORD ppid,
    IN BOOL block_dlls)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOL success = FALSE;
    BOOL ret_val = FALSE;
    WCHAR nt_process_image[MAX_PATH] = { 0 };
    PS_CREATE_INFO ci = { 0 };

    memset(nt_process_image, 0, sizeof(WCHAR) * MAX_PATH);
    swprintf_s(nt_process_image, MAX_PATH, L"\\??\\%ws", process_image);

    if (use_ntcreateuserproc)
    {
        // call NtCreateUserProcess
        success = create_process_with_ntcreateuserproc(
            pi,
            &ci,
            process_image,
            nt_process_image,
            wparams,
            wdirectory,
            ppid,
            block_dlls);

        if (!success)
        {
            PRINT_ERR("Failed to create the process\n");
            goto cleanup;
        }
    }
    else
    {
        // call NtCreateProcessEx
        success = create_process_with_ntcreateprocex(
            pi,
            &ci,
            process_image,
            nt_process_image,
            wparams,
            wdirectory,
            ppid,
            block_dlls);

        if (!success)
        {
            PRINT_ERR("Failed to create the process\n");
            goto cleanup;
        }
    }


    PRINT("[+] New process created\n");
    PRINT("[i] hProcess = 0x%p\n", pi->hProcess);
    PRINT("[i]  hThread = 0x%p\n", pi->hThread);
    PRINT("[i]      PID = %ld\n", pi->dwProcessId);
    PRINT("[i]      TID = %ld\n", pi->dwThreadId);
    PRINT("[i]      PEB = 0x%p\n", (PVOID)(ULONG_PTR)ci.SuccessState.PebAddressNative);

    // register the new process with the CSRSS

    status = register_with_csr(
        pi,
        &ci,
        process_image,
        nt_process_image);

    if (!NT_SUCCESS(status))
    {
        PRINT_ERR("Could not register process with the CSRSS\n");
        goto cleanup;
    }

    // resume if suspended flag was not provided
    if (!suspended)
    {
        status = _NtResumeThread(pi->hThread, 0);

        if (!NT_SUCCESS(status))
        {
            PRINT_ERR("Could resume the process, status: 0x%lx\n", status);
            goto cleanup;
        }
        PRINT("[+] Resumed process\n");
    }

    ret_val = TRUE;

cleanup:
    if (ci.SuccessState.FileHandle)
        _NtClose(ci.SuccessState.FileHandle);

    return ret_val;
}

BOOL is_win_6_point_0_or_grater(VOID)
{
    PVOID pPeb;
    ULONG32 OSMajorVersion;

    pPeb = (PVOID)READ_MEMLOC(PEB_OFFSET);
    OSMajorVersion = *RVA2VA(PULONG32, pPeb, OSMAJORVERSION_OFFSET);

    if (OSMajorVersion >= 6)
        return TRUE;

    return FALSE;
}

VOID usage(
    IN LPCSTR procname)
{
    PRINT("usage: %s --binary C:\\Windows\\notepad.exe [--syscall NtCreateUserProcess] [--params \"--some params\"] [--directory C:\\Windows\\Temp] [--suspended] [--ppid 1234] [--blockdlls] [--help]\n", procname);
    PRINT("    --binary BIN_PATH, -b BIN_PATH\n");
    PRINT("            full path of the binary to run\n");
    PRINT("    --syscall {NtCreateUserProcess,NtCreateProcessEx}\n");
    PRINT("            create the process using NtCreateUserProcess (default) or NtCreateProcessEx\n");
    PRINT("    --params PARAMS, -p PARAMS\n");
    PRINT("            parameters of the new process\n");
    PRINT("    --directory DIR, -d DIR\n");
    PRINT("            the current working directory that should be assigned to the process\n");
    PRINT("    --suspended, -s\n");
    PRINT("            create the process in a suspended state\n");
    PRINT("    --ppid NUM, -pp NUM\n");
    PRINT("            the PID of the parent process\n");
    PRINT("    --blockdlls, -bd\n");
    PRINT("            only allow Microsoft DLLs to be loaded\n");
    PRINT("    --help, -h\n");
    PRINT("            print this help message and leave\n");
}

int main(int argc, char* argv[])
{
    LPCSTR binary                = NULL;
    BOOL   use_ntcreateuserproc  = TRUE;
    LPCSTR parameters            = NULL;
    LPCSTR directory             = NULL;
    BOOL   suspended             = FALSE;
    BOOL   block_dlls            = FALSE;
    DWORD  ppid                  = 0;
    WCHAR  wbinary[MAX_PATH]    = { 0 };
    WCHAR  wparams[MAX_PATH]    = { 0 };
    WCHAR  wdirectory[MAX_PATH] = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    BOOL success = FALSE;

    for (int i = 1; i < argc; ++i)
    {
        if (!strncmp(argv[i], "-b", 3) ||
                 !strncmp(argv[i], "--binary", 9))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --binary value\n");
                return 0;
            }
            binary = argv[++i];
            mbstowcs(wbinary, binary, MAX_PATH);
        }
        else if (!strncmp(argv[i], "--syscall", 10))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --syscall value\n");
                return 0;
            }
            i++;
            if (!strncmp(argv[i], "NtCreateUserProcess", 20))
            {
                use_ntcreateuserproc = TRUE;
            }
            else if (!strncmp(argv[i], "NtCreateProcessEx", 18))
            {
                use_ntcreateuserproc = FALSE;
            }
            else
            {
                printf("invalid --syscall value\n");
                return 0;
            }
        }
        else if (!strncmp(argv[i], "-p", 3) ||
                 !strncmp(argv[i], "--params", 9))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --params value\n");
                return 0;
            }
            parameters = argv[++i];
            mbstowcs(wparams, parameters, MAX_PATH);
        }
        else if (!strncmp(argv[i], "-d", 3) ||
                 !strncmp(argv[i], "--directory", 12))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --directory value\n");
                return 0;
            }
            directory = argv[++i];
            mbstowcs(wdirectory, directory, MAX_PATH);
        }
        else if (!strncmp(argv[i], "-s", 3) ||
                 !strncmp(argv[i], "--suspended", 12))
        {
            suspended = TRUE;
        }
        else if (!strncmp(argv[i], "-pp", 4) ||
                 !strncmp(argv[i], "--ppid", 7))
        {
            if (i + 1 >= argc)
            {
                PRINT("missing --ppid value\n");
                return 0;
            }
            ppid = atoi(argv[++i]);
            if (!ppid)
            {
                PRINT("invalid ppid\n")
                return 0;
            }
        }
        else if (!strncmp(argv[i], "-bd", 4) ||
                 !strncmp(argv[i], "--blockdlls", 12))
        {
            block_dlls = TRUE;
        }
        else if (!strncmp(argv[i], "-h", 3) ||
                 !strncmp(argv[i], "--help", 7))
        {
            usage(argv[0]);
            return 0;
        }
        else
        {
            PRINT("invalid argument: %s\n", argv[i]);
            return 0;
        }
    }
    if (!binary)
    {
        usage(argv[0]);
        return 0;
    }

    if (use_ntcreateuserproc && !is_win_6_point_0_or_grater())
    {
        PRINT("The NtCreateUserProcess syscall is not supported on this system, use NtCreateProcessEx\n");
        return 0;
    }

    if (!use_ntcreateuserproc && block_dlls)
    {
        PRINT("The --blockdlls option is not supported while using NtCreateProcessEx\n");
        return 0;
    }

    success = create_process_internal(
        &pi,
        use_ntcreateuserproc,
        wbinary,
        parameters ? wparams : NULL,
        directory ? wdirectory : NULL,
        suspended,
        ppid,
        block_dlls);

    if (success)
    {
        if (pi.hProcess)
            _NtClose(pi.hProcess);
        if (pi.hThread)
            _NtClose(pi.hThread);
    }

    return 0;
}
