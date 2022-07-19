#pragma once

#include <windows.h>
#include "ntdefs.h"

#define CSR_MAKE_API_NUMBER( DllIndex, ApiIndex ) \
    (CSR_API_NUMBER)(((DllIndex) << 16) | (ApiIndex))

#define CSRSRV_SERVERDLL_INDEX          0
#define CSRSRV_FIRST_API_NUMBER         0

#define BASESRV_SERVERDLL_INDEX         1
#define BASESRV_FIRST_API_NUMBER        0

#define CONSRV_SERVERDLL_INDEX          2
#define CONSRV_FIRST_API_NUMBER         512

#define USERSRV_SERVERDLL_INDEX         3
#define USERSRV_FIRST_API_NUMBER        1024

typedef enum _BASESRV_API_NUMBER
{
	BasepCreateProcess = BASESRV_FIRST_API_NUMBER,
	BasepCreateThread,
	BasepGetTempFile,
	BasepExitProcess,
	BasepDebugProcess,
	BasepCheckVDM,
	BasepUpdateVDMEntry,
	BasepGetNextVDMCommand,
	BasepExitVDM,
	BasepIsFirstVDM,
	BasepGetVDMExitCode,
	BasepSetReenterCount,
	BasepSetProcessShutdownParam,
	BasepGetProcessShutdownParam,
	BasepNlsSetUserInfo,
	BasepNlsSetMultipleUserInfo,
	BasepNlsCreateSection,
	BasepSetVDMCurDirs,
	BasepGetVDMCurDirs,
	BasepBatNotification,
	BasepRegisterWowExec,
	BasepSoundSentryNotification,
	BasepRefreshIniFileMapping,
	BasepDefineDosDevice,
	BasepSetTermsrvAppInstallMode,
	BasepNlsUpdateCacheCount,
	BasepSetTermsrvClientTimeZone,
	BasepSxsCreateActivationContext,
	BasepDebugProcessStop,
	BasepRegisterThread,
	BasepNlsGetUserInfo,
} BASESRV_API_NUMBER, * PBASESRV_API_NUMBER;

typedef struct
{
	BYTE byte0;						// +00
	BYTE byte1;						// +01
	BYTE byte2;						// +02
	BYTE byte3;						// +02
	ULONG64 DUMMY;					// +08
	ULONG_PTR ManifestAddress;		// +10
	ULONG64 ManifestSize;			// +18
	HANDLE SectionHandle;			// +20
	ULONG64 Offset;					// +28
	ULONG_PTR Size;					// +30
} BASE_SXS_STREAM;					// 0x38

typedef struct
{
	ULONG Flags;					// +00      // direct set, value = 0x40
	ULONG ProcessParameterFlags;	// +04      // direct set, value = 0x4001
	HANDLE FileHandle;				// +08      // we can get this value
	UNICODE_STRING SxsWin32ExePath;	// +10      // UNICODE_STRING, we can build!
	UNICODE_STRING SxsNtExePath;	// +20      // UNICODE_STRING, we can build!
	BYTE    Field30[0x10];          // +30      // blank, ignore
	BASE_SXS_STREAM PolicyStream;	// +40      // !!!
	UNICODE_STRING AssemblyName;	// +78      // blank, ignore
	UNICODE_STRING FileName3;		// +88      // UNICODE_STRING, we can build!
	BYTE    Field98[0x10];			// +98      // blank, ignore
	UNICODE_STRING FileName4;		// +a8      // UNICODE_STRING, we can build!
	BYTE OtherFileds[0x110];		// +b8		// blank, ignore
} BASE_SXS_CREATEPROCESS_MSG;		// 0x1C8

typedef struct {
	HANDLE ProcessHandle;			// +00      // can get
	HANDLE ThreadHandle;			// +08      // can get
	CLIENT_ID ClientId;				// +10      // can get, PID, TID
	ULONG CreationFlags;			// +20      // direct set, must be zero
	ULONG VdmBinaryType;			// +24      // direct set, must be zero
	ULONG VdmTask;					// +28      // ignore
	//ULONG_PTR VdmTask;					// modified value
	HANDLE hVDM;					// +30      // ignore
	BASE_SXS_CREATEPROCESS_MSG Sxs;	// +38      // deep, need analyze, (for BASE_API_MSG, start with 0x78)
	ULONG64 PebAddressNative;       // +200     // can get
	ULONG_PTR PebAddressWow64;		// +208     // direct set, must be zero (Win64 limit)
	USHORT ProcessorArchitecture;	// +210     // direct set, must be 9 (AMD64 limit)
} BASE_CREATEPROCESS_MSG;

////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef CSHORT
#define CSHORT short
#endif

typedef struct _CSR_CAPTURE_HEADER {
	ULONG Length;
	PVOID RelatedCaptureBuffer;         // real: PCSR_CAPTURE_HEADER
	ULONG CountMessagePointers;
	PCHAR FreeSpace;
	ULONG_PTR MessagePointerOffsets[1]; // Offsets within CSR_API_MSG of pointers
} CSR_CAPTURE_HEADER, * PCSR_CAPTURE_HEADER;

typedef ULONG CSR_API_NUMBER;

////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct _PORT_MESSAGE_HEADER
{
	union
	{
		struct
		{
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		SIZE_T ClientViewSize;
		ULONG CallbackId;
	};
} PORT_MESSAGE_HEADER, * PPORT_MESSAGE_HEADER;

typedef struct _PORT_MESSAGE {
	PORT_MESSAGE_HEADER Header;                 // 0x00
	PCSR_CAPTURE_HEADER CaptureBuffer;			// 0x28 
	CSR_API_NUMBER ApiNumber;					// 0x30 
	ULONG ReturnValue;							// 0x34 
	ULONG64 Reserved;							// 0x38
} PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct {
	PORT_MESSAGE PortHeader;
	BASE_CREATEPROCESS_MSG CreateProcessMSG;		// 0x40
} BASE_API_MSG, *PBASE_API_MSG;

typedef struct _CSR_CAPTURE_BUFFER
{
	ULONG Size;
	struct _CSR_CAPTURE_BUFFER* PreviousCaptureBuffer;
	ULONG PointerCount;
	PVOID BufferEnd;
	ULONG_PTR PointerOffsetsArray[ANYSIZE_ARRAY];
} CSR_CAPTURE_BUFFER, * PCSR_CAPTURE_BUFFER;
