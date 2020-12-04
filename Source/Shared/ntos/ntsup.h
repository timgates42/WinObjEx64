/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2011 - 2020 UGN/HE
*
*  TITLE:       NTSUP.H
*
*  VERSION:     2.04
*
*  DATE:        30 Nov 2020
*
*  Common header file for the NT API support functions and definitions.
*
*  Depends on:    ntos.h
*                 minirtl
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#define ENABLE_C_EXTERN

#if defined (_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#ifndef NTSUP_RTL
#define NTSUP_RTL

#pragma warning(push)
#pragma warning(disable: 4201) // nameless struct/union
#pragma warning(disable: 4214) // nonstandard extension used : bit field types other than int

#ifndef _WINDOWS_
#include <Windows.h>
#endif

#pragma warning(push)
#pragma warning(disable: 4005) //macro redefinition
#include <ntstatus.h>
#pragma warning(pop)

#include "ntos.h"

#define _NTDEF_
#include <ntsecapi.h>
#undef _NTDEF_

#include "minirtl/minirtl.h"
#include "minirtl/rtltypes.h"

#ifdef ENABLE_C_EXTERN
#if defined(__cplusplus)
extern "C" {
#endif
#endif

typedef NTSTATUS(NTAPI* PFN_NTQUERYROUTINE)(
   _In_ HANDLE ObjectHandle,
   _In_ DWORD InformationClass,
   _Out_writes_bytes_(ObjectInformationLength) PVOID ObjectInformation,
   _In_ ULONG ObjectInformationLength,
   _Out_opt_ PULONG ReturnLength);

typedef PVOID(CALLBACK* PNTSUPMEMALLOC)(
    _In_ SIZE_T NumberOfBytes);

typedef BOOL(CALLBACK* PNTSUPMEMFREE)(
    _In_ PVOID Memory);

#define ntsupProcessHeap() NtCurrentPeb()->ProcessHeap

#define NTQSI_MAX_BUFFER_LENGTH (512 * 1024 * 1024)

PVOID ntsupHeapAlloc(
    _In_ SIZE_T Size);

VOID ntsupHeapFree(
    _In_ PVOID BaseAddress);

PVOID ntsupVirtualAllocEx(
    _In_ SIZE_T Size,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect);

PVOID ntsupVirtualAlloc(
    _In_ SIZE_T Size);

BOOL ntsupVirtualFree(
    _In_ PVOID Memory);

SIZE_T ntsupWriteBufferToFile(
    _In_ PWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ SIZE_T Size,
    _In_ BOOL Flush,
    _In_ BOOL Append);

PVOID ntsupFindModuleEntryByName(
    _In_ PRTL_PROCESS_MODULES pModulesList,
    _In_ LPCSTR ModuleName);

BOOL ntsupFindModuleEntryByAddress(
    _In_ PRTL_PROCESS_MODULES pModulesList,
    _In_ PVOID Address,
    _Out_ PULONG ModuleIndex);

BOOL ntsupFindModuleNameByAddress(
    _In_ PRTL_PROCESS_MODULES pModulesList,
    _In_ PVOID Address,
    _Inout_	LPWSTR Buffer,
    _In_ DWORD ccBuffer);

NTSTATUS ntsupConvertToUnicode(
    _In_ LPCSTR AnsiString,
    _Inout_ PUNICODE_STRING UnicodeString);

NTSTATUS ntsupConvertToAnsi(
    _In_ LPCWSTR UnicodeString,
    _Inout_ PANSI_STRING AnsiString);

BOOLEAN ntsupEnablePrivilege(
    _In_ DWORD Privilege,
    _In_ BOOLEAN Enable);

HANDLE ntsupGetCurrentProcessToken(
    VOID);

ULONG_PTR ntsupQuerySystemRangeStart(
    VOID);

BOOL ntsupIsProcess32bit(
    _In_ HANDLE hProcess);

PVOID ntsupGetSystemInfoEx(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PULONG ReturnLength,
    _In_ PNTSUPMEMALLOC AllocMem,
    _In_ PNTSUPMEMFREE FreeMem);

PVOID ntsupGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_opt_ PULONG ReturnLength);

BOOL ntsupResolveSymbolicLink(
    _In_opt_ HANDLE RootDirectoryHandle,
    _In_ PUNICODE_STRING LinkName,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD cbBuffer);

BOOL ntsupQueryThreadWin32StartAddress(
    _In_ HANDLE ThreadHandle,
    _Out_ PULONG_PTR Win32StartAddress);

HANDLE ntsupOpenDirectory(
    _In_opt_ HANDLE RootDirectoryHandle,
    _In_ LPWSTR DirectoryName,
    _In_ ACCESS_MASK DesiredAccess);

BOOL ntsupQueryProcessName(
    _In_ ULONG_PTR dwProcessId,
    _In_ PVOID ProcessList,
    _Inout_ LPWSTR Buffer,
    _In_ DWORD ccBuffer);

BOOL ntsupQueryProcessEntryById(
    _In_ HANDLE UniqueProcessId,
    _In_ PVOID ProcessList,
    _Out_ PSYSTEM_PROCESSES_INFORMATION* Entry);

NTSTATUS ntsupQueryProcessInformation(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_ PVOID* Buffer,
    _Out_opt_ PULONG ReturnLength,
    _In_ PNTSUPMEMALLOC AllocMem,
    _In_ PNTSUPMEMFREE FreeMem);

NTSTATUS ntsupQueryObjectInformation(
    _In_ HANDLE ObjectHandle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_ PVOID* Buffer,
    _Out_opt_ PULONG ReturnLength,
    _In_ PNTSUPMEMALLOC AllocMem,
    _In_ PNTSUPMEMFREE FreeMem);

NTSTATUS ntsupQuerySecurityInformation(
    _In_ HANDLE ObjectHandle,
    _In_ SECURITY_INFORMATION SecurityInformationClass,
    _Out_ PVOID* Buffer,
    _Out_opt_ PULONG ReturnLength,
    _In_ PNTSUPMEMALLOC AllocMem,
    _In_ PNTSUPMEMFREE FreeMem);

NTSTATUS ntsupQuerySystemObjectInformationVariableSize(
    _In_ PFN_NTQUERYROUTINE QueryRoutine,
    _In_ HANDLE ObjectHandle,
    _In_ DWORD InformationClass,
    _Out_ PVOID* Buffer,
    _Out_opt_ PULONG ReturnLength,
    _In_ PNTSUPMEMALLOC AllocMem,
    _In_ PNTSUPMEMFREE FreeMem);

BOOLEAN ntsupQueryHVCIState(
    _Out_ PBOOLEAN pbHVCIEnabled,
    _Out_ PBOOLEAN pbHVCIStrictMode,
    _Out_ PBOOLEAN pbHVCIIUMEnabled);

PVOID ntsupLookupImageSectionByName(
    _In_ CHAR* SectionName,
    _In_ ULONG SectionNameLength,
    _In_ PVOID DllBase,
    _Out_ PULONG SectionSize);

PVOID ntsupFindPattern(
    _In_ CONST PBYTE Buffer,
    _In_ SIZE_T BufferSize,
    _In_ CONST PBYTE Pattern,
    _In_ SIZE_T PatternSize);

NTSTATUS ntsupOpenProcess(
    _In_ HANDLE UniqueProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ProcessHandle);

NTSTATUS ntsupOpenThread(
    _In_ PCLIENT_ID ClientId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ PHANDLE ThreadHandle);

NTSTATUS ntsupCICustomKernelSignersAllowed(
    _Out_ PBOOLEAN bAllowed);

NTSTATUS ntsupPrivilegeEnabled(
    _In_ HANDLE ClientToken,
    _In_ ULONG Privilege,
    _Out_ LPBOOL pfResult);

LPWSTR ntsupQueryEnvironmentVariableOffset(
    _In_ PUNICODE_STRING Value);

DWORD ntsupExpandEnvironmentStrings(
    _In_ LPCWSTR lpSrc,
    _Out_writes_to_opt_(nSize, return) LPWSTR lpDst,
    _In_ DWORD nSize);

NTSTATUS ntsupIsLocalSystem(
    _Out_ PBOOL pbResult);

NTSTATUS ntsupIsUserHasInteractiveSid(
    _In_ HANDLE hToken,
    _Out_ PBOOL pbInteractiveSid);

BOOL ntsupGetProcessElevationType(
    _In_opt_ HANDLE ProcessHandle,
    _Out_ TOKEN_ELEVATION_TYPE * lpType);

NTSTATUS ntsupIsProcessElevated(
    _In_ ULONG ProcessId,
    _Out_ PBOOL Elevated);

ULONG ntsupGetMappedFileName(
    _In_ PVOID BaseAddress,
    _Inout_ LPWSTR FileName,
    _In_ ULONG cchFileName,
    _Out_ PSIZE_T cbNeeded);

VOID ntsupPurgeSystemCache(
    VOID);

NTSTATUS ntsupGetProcessDebugObject(
    _In_ HANDLE ProcessHandle,
    _Out_ PHANDLE DebugObjectHandle);

PBYTE ntsupQueryResourceData(
    _In_ ULONG_PTR ResourceId,
    _In_ PVOID DllHandle,
    _In_ PULONG DataSize);

NTSTATUS ntsupEnableWow64Redirection(
    _In_ BOOLEAN bEnable);

BOOLEAN ntsupIsKdEnabled(
    _Out_opt_ PBOOLEAN DebuggerAllowed,
    _Out_opt_ PBOOLEAN DebuggerNotPresent);

#ifdef ENABLE_C_EXTERN
#ifdef __cplusplus
}
#endif
#endif

#pragma warning(pop)

#endif NTSUP_RTL
