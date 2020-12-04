/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       SDVIEWDLG.C
*
*  VERSION:     1.88
*
*  DATE:        01 Dec 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "sdviewDlg.h"

typedef VOID(CALLBACK* pfnGroupOutputCallback)(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ LPWSTR Information
    );

typedef VOID(CALLBACK* pfnAclOutputCallback)(
    _In_ SDVIEW_CONTEXT* Context
    //TBD
    );

VOID FreeSDViewContext(
    _In_ SDVIEW_CONTEXT* SdViewContext
)
{
    if (SdViewContext->Name)
        supHeapFree(SdViewContext->Name);
    if (SdViewContext->Directory)
        supHeapFree(SdViewContext->Directory);

    supHeapFree(SdViewContext);
}

SDVIEW_CONTEXT* AllocateSDViewContext(
    _In_ LPWSTR ObjectDirectory,
    _In_opt_ LPWSTR ObjectName,
    _In_ WOBJ_OBJECT_TYPE ObjectType
)
{
    SDVIEW_CONTEXT* ctx;
    SIZE_T nLen, nNameLen = 0;

    nLen = _strlen(ObjectDirectory);
    if (nLen == 0)
        return NULL;

    if (ObjectName) {
        nNameLen = _strlen(ObjectName);
        if (nNameLen == 0)
            return NULL;
    }

    ctx = (SDVIEW_CONTEXT*)supHeapAlloc(sizeof(SDVIEW_CONTEXT));
    if (ctx == NULL)
        return NULL;

    ctx->Directory = (LPWSTR)supHeapAlloc((1 + nLen) * sizeof(WCHAR));
    if (ctx->Directory == NULL) {
        FreeSDViewContext(ctx);
        return NULL;
    }

    _strcpy(ctx->Directory, ObjectDirectory);

    ctx->Type = ObjectType;

    if (ObjectName) {

        ctx->Name = (LPWSTR)supHeapAlloc((1 + nNameLen) * sizeof(WCHAR));
        if (ctx->Name == NULL) {
            FreeSDViewContext(ctx);
            return NULL;
        }

        _strcpy(ctx->Name, ObjectName);
    }

    return ctx;
}

//TBD
VOID SdViewShowNtError(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ NTSTATUS NtError
)
{
    //FIXME
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(NtError);
}

//TBD
VOID SdViewDumpAceList(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ ULONG AceCount,
    _In_ PVOID FirstAce,
    _In_ LSA_HANDLE PolicyHandle
)
{
//FIXME
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(AceCount);
    UNREFERENCED_PARAMETER(FirstAce);
    UNREFERENCED_PARAMETER(PolicyHandle);
}

//TBD
VOID SdViewDumpAcl(
    _In_ SDVIEW_CONTEXT* Context,
    _In_opt_ PACL Acl,
    _In_ LSA_HANDLE PolicyHandle
)
{
    PVOID firstAce = NULL;

    //FIXME
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(PolicyHandle);

    if (Acl == NULL) {


    }
    else {

        if (Acl->AceCount == 0) {



        }
        else {

            if (NT_SUCCESS(RtlGetAce(Acl, 0, &firstAce))) {

                SdViewDumpAceList(Context, Acl->AceCount, firstAce, PolicyHandle);

            }

        }

    }
}

VOID SdViewDumpTokenGroups(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ PTOKEN_GROUPS TokenGroups,
    _In_ LSA_HANDLE PolicyHandle,
    _In_ pfnGroupOutputCallback OutputCallback
)
{
    ULONG groupCount, domainIndex, i, groupAttributes;
    NTSTATUS ntStatus;
    PSID_AND_ATTRIBUTES tokenGroups = NULL;
    PLSA_TRANSLATED_NAME translatedNames = NULL, pNames;
    PLSA_REFERENCED_DOMAIN_LIST referencedDomains = NULL;
    PUNICODE_STRING pusDomainName, pusName;
    PSID* lookupSids;
    LPWSTR pSidNameUseString = NULL;

    UNICODE_STRING stringSid, usEmpty;

    SID_NAME_USE sidNameUse;

    WCHAR szBuffer[512];
    WCHAR szAttrList[10];

    //
    // Do we have anything to show?
    //
    if (!TokenGroups->GroupCount)
        return;

    tokenGroups = TokenGroups->Groups;
    groupCount = TokenGroups->GroupCount;

    //
    // Allocate array of sids for LsaLookupSids.
    //
    lookupSids = (PSID*)supHeapAlloc(groupCount * sizeof(PSID));
    if (lookupSids == NULL)
        return;

    __try {

        //
        // Fill sids array for LsaLookupSids.
        //
        for (i = 0; i < groupCount; i++, tokenGroups++)
            lookupSids[i] = tokenGroups->Sid;

        ntStatus = LsaLookupSids(PolicyHandle,
            groupCount,
            lookupSids,
            &referencedDomains,
            &translatedNames);

        if (!NT_SUCCESS(ntStatus)) {
            __leave;
        }

        pNames = translatedNames;
        tokenGroups = TokenGroups->Groups;

        RtlInitEmptyUnicodeString(&stringSid, NULL, 0);
        RtlInitEmptyUnicodeString(&usEmpty, NULL, 0);

        for (i = 0; i < groupCount; i++, tokenGroups++) {

            //
            // Convert SID to string, on failure zero result so RtlFreeUnicodeString won't fuckup.
            //
            if (!NT_SUCCESS(RtlConvertSidToUnicodeString(&stringSid,
                tokenGroups->Sid,
                TRUE)))
            {
                stringSid.Buffer = NULL;
                stringSid.Length = 0;
            }

            pusDomainName = &usEmpty;
            pusName = &usEmpty;
            sidNameUse = SidTypeUnknown;

            //
            // Link domain, name and sid name use.
            //
            if (pNames) {

                domainIndex = pNames->DomainIndex;
                if (domainIndex < referencedDomains->Entries)
                    pusDomainName = &referencedDomains->Domains[domainIndex].Name;

                pusName = &pNames->Name;
                sidNameUse = pNames->Use;
                pNames++;

            }

            RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
            pSidNameUseString = supGetSidUseName(sidNameUse);

            groupAttributes = tokenGroups->Attributes;
            if (groupAttributes) {

                //
                // Dump group attributes.
                //
                szAttrList[0] = groupAttributes & SE_GROUP_MANDATORY ? L'M' : L' ';
                szAttrList[1] = groupAttributes & SE_GROUP_ENABLED ? L'E' : L' ';
                szAttrList[2] = groupAttributes & SE_GROUP_ENABLED_BY_DEFAULT ? L'+' : L' ';
                szAttrList[3] = groupAttributes & SE_GROUP_OWNER ? L'O' : L' ';
                szAttrList[4] = groupAttributes & SE_GROUP_USE_FOR_DENY_ONLY ? L'D' : L' ';
                szAttrList[5] = groupAttributes & SE_GROUP_INTEGRITY ? L'I' : L' ';
                szAttrList[6] = groupAttributes & SE_GROUP_INTEGRITY_ENABLED ? L'+' : L' ';
                szAttrList[7] = groupAttributes & SE_GROUP_LOGON_ID ? L'L' : L' ';
                szAttrList[8] = groupAttributes & SE_GROUP_RESOURCE ? L'R' : L' ';
                szAttrList[9] = 0;

                //
                // Dump sid name use.
                //
                switch (sidNameUse) {

                case SidTypeInvalid:
                case SidTypeUnknown:

                    RtlStringCchPrintfSecure(szBuffer,
                        RTL_NUMBER_OF(szBuffer),
                        TEXT("0x%08X %wS [%wZ] [%wS]"),
                        groupAttributes,
                        szAttrList,
                        &stringSid,
                        pSidNameUseString);

                    break;

                default:

                    RtlStringCchPrintfSecure(szBuffer,
                        RTL_NUMBER_OF(szBuffer),
                        TEXT(" 0x%08X %wS [%wZ] '%wZ\\%wZ' [%wS]"),
                        groupAttributes,
                        szAttrList,
                        &stringSid,
                        pusDomainName,
                        pusName,
                        pSidNameUseString);

                    break;
                }

            }
            else {


                //
                // Dump sid name use.
                //
                switch (sidNameUse) {
                case SidTypeInvalid:
                case SidTypeUnknown:

                    RtlStringCchPrintfSecure(szBuffer,
                        RTL_NUMBER_OF(szBuffer),
                        TEXT("[%wZ] [%wS]"),
                        &stringSid,
                        pSidNameUseString);

                    break;

                default:

                    RtlStringCchPrintfSecure(szBuffer,
                        RTL_NUMBER_OF(szBuffer),
                        TEXT("[%wZ] '%wZ\\%wZ' [%wS]"),
                        &stringSid,
                        pusDomainName,
                        pusName,
                        pSidNameUseString);

                    break;
                }

            }

            RtlFreeUnicodeString(&stringSid);
            OutputCallback(Context, szBuffer);
        }

    }
    __finally {
        supHeapFree(lookupSids);
        if (referencedDomains) LsaFreeMemory(referencedDomains);
        if (translatedNames) LsaFreeMemory(translatedNames);
    }
}

VOID CALLBACK SdViewOutputSidCallback(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ LPWSTR SidInformation
)
{
    SetDlgItemText(Context->DialogWindow, IDC_SDVIEW_OWNER, SidInformation);
}

/*
* SdViewDumpSid
*
* Purpose:
*
* Output SID information.
*
*/
VOID SdViewDumpSid(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ PSID Sid,
    _In_ LSA_HANDLE PolicyHandle
)
{
    TOKEN_GROUPS tkGroups;

    tkGroups.GroupCount = 1;
    tkGroups.Groups[0].Attributes = 0;
    tkGroups.Groups[0].Sid = Sid;

    SdViewDumpTokenGroups(Context, &tkGroups, PolicyHandle, &SdViewOutputSidCallback);
}

/*
* SdViewDumpObjectSecurity
*
* Purpose:
*
* Dump object security information (dacl, sacl, sid).
*
*/
NTSTATUS SdViewDumpObjectSecurity(
    _In_ SDVIEW_CONTEXT* Context
)
{
    NTSTATUS ntStatus, ntQueryStatus;
    HANDLE hObject = NULL;
    LSA_HANDLE hPolicy = NULL;
    LSA_OBJECT_ATTRIBUTES lsaOa;

    PACL pAcl;
    PSID pOwnerSid;
    PSECURITY_DESCRIPTOR pSD = NULL;

    BOOLEAN bDefaulted = FALSE, bPresent = FALSE;

    __try {

        ntStatus = supOpenNamedObjectByType(&hObject,
            Context->Type,
            Context->Directory,
            Context->Name,
            READ_CONTROL);

        if (!NT_SUCCESS(ntStatus))
            __leave;

        InitializeObjectAttributes((OBJECT_ATTRIBUTES*)&lsaOa, NULL, 0, 0, NULL);

        ntStatus = LsaOpenPolicy(NULL, &lsaOa, POLICY_LOOKUP_NAMES, &hPolicy);
        if (!NT_SUCCESS(ntStatus))
            __leave;

        ntStatus = supQuerySecurityInformation(
            hObject,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
            LABEL_SECURITY_INFORMATION | PROCESS_TRUST_LABEL_SECURITY_INFORMATION,
            &pSD,
            NULL,
            (PNTSUPMEMALLOC)supHeapAlloc,
            (PNTSUPMEMFREE)supHeapFree);

        if (!NT_SUCCESS(ntStatus))
            __leave;


        pOwnerSid = NULL;
        ntQueryStatus = RtlGetOwnerSecurityDescriptor(pSD, &pOwnerSid, &bDefaulted);
        if (NT_SUCCESS(ntQueryStatus)) {

            SdViewDumpSid(Context, pOwnerSid, hPolicy);

        }

        pAcl = NULL;
        ntQueryStatus = RtlGetDaclSecurityDescriptor(pSD, &bPresent, &pAcl, &bDefaulted);
        if (NT_SUCCESS(ntQueryStatus)) {

            SdViewDumpAcl(Context, pAcl, hPolicy);

        }

        pAcl = NULL;
        ntQueryStatus = RtlGetSaclSecurityDescriptor(pSD, &bPresent, &pAcl, &bDefaulted);
        if (NT_SUCCESS(ntQueryStatus)) {

            SdViewDumpAcl(Context, pAcl, hPolicy);

        }

    }
    __finally {
        if (pSD) supHeapFree(pSD);
        if (hPolicy) LsaClose(hPolicy);
        if (hObject) NtClose(hObject);
    }

    return ntStatus;
}

/*
* SDViewInitControls
*
* Purpose:
*
* Initialize controls.
*
*/
VOID SDViewInitControls(
    _In_ HWND hwndDlg
)
{
    HWND aclList = GetDlgItem(hwndDlg, IDC_SDVIEW_LIST);
    HWND sidOwner = GetDlgItem(hwndDlg, IDC_SDVIEW_OWNER);

    ListView_SetExtendedListViewStyle(aclList,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);

    SendMessage(aclList, LVM_ENABLEGROUPVIEW, 1, 0);

    SetWindowTheme(aclList, TEXT("Explorer"), NULL);

    supAddListViewColumn(aclList, 0, 0, 0,
        I_IMAGENONE,
        LVCFMT_LEFT,
        TEXT("Type"), 80);

    supAddListViewColumn(aclList, 1, 1, 1,
        I_IMAGENONE,
        LVCFMT_LEFT,
        TEXT("Flags"), 80);

    supAddListViewColumn(aclList, 2, 2, 2,
        I_IMAGENONE,
        LVCFMT_LEFT,
        TEXT("AccessMask"), 120);

    supAddListViewColumn(aclList, 3, 3, 3,
        I_IMAGENONE,
        LVCFMT_LEFT,
        TEXT("SID"), 400);


    SetWindowText(sidOwner, T_EmptyString);

    //FIXME
}

/*
* SDViewDialogProc
*
* Purpose:
*
* View Security Descriptor Dialog Window Procedure
*
* During WM_INITDIALOG centers window and initializes security descriptor info
*
*/
INT_PTR CALLBACK SDViewDialogProc(
    _In_ HWND   hwndDlg,
    _In_ UINT   uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    SDVIEW_CONTEXT* sdvContext;

    switch (uMsg) {

    case WM_INITDIALOG:
        supCenterWindow(hwndDlg);
        if (lParam) {
            sdvContext = (SDVIEW_CONTEXT*)lParam;
            SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)lParam);
        }
        SDViewInitControls(hwndDlg);
        break;

    case WM_CLOSE:
        sdvContext = (SDVIEW_CONTEXT*)RemoveProp(hwndDlg, T_DLGCONTEXT);
        if (sdvContext) {
            if (sdvContext->DialogIcon)
                DestroyIcon(sdvContext->DialogIcon);

            FreeSDViewContext(sdvContext);
        }
        return DestroyWindow(hwndDlg);

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {
        case IDCANCEL:
        case IDOK:
            SendMessage(hwndDlg, WM_CLOSE, 0, 0);
            return TRUE;
        default:
            break;
        }

    default:
        return FALSE;
    }

    return TRUE;
}

/*
* SDViewDialogCreate
*
* Purpose:
*
* Create and initialize ViewSecurityDescriptor Dialog.
*
*/
VOID SDViewDialogCreate(
    _In_ HWND ParentWindow,
    _In_ LPWSTR ObjectDirectory,
    _In_opt_ LPWSTR ObjectName,
    _In_ WOBJ_OBJECT_TYPE ObjectType
)
{
    HICON hIcon;
    HWND hwndDlg;
    NTSTATUS ntStatus;
    SDVIEW_CONTEXT* SDViewContext;

    LPWSTR lpCaption;
    SIZE_T nLen;

    ENUMCHILDWNDDATA wndData;

    if (ObjectDirectory == NULL)
        return;

    SDViewContext = AllocateSDViewContext(ObjectDirectory,
        ObjectName,
        ObjectType);

    if (SDViewContext == NULL)
        return;

    hwndDlg = CreateDialogParam(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDD_DIALOG_SDVIEW),
        ParentWindow,
        (DLGPROC)&SDViewDialogProc,
        (LPARAM)SDViewContext);

    if (hwndDlg) {

        nLen = MAX_PATH + _strlen(SDViewContext->Name) +
            _strlen(SDViewContext->Directory);

        lpCaption = (LPWSTR)supHeapAlloc(nLen * sizeof(WCHAR));
        if (lpCaption) {

            _strcpy(lpCaption, SDViewContext->Directory);
            if (SDViewContext->Name) {
                if (_strcmpi(SDViewContext->Directory, KM_OBJECTS_ROOT_DIRECTORY) != 0)
                    _strcat(lpCaption, TEXT("\\"));
                _strcat(lpCaption, SDViewContext->Name);
            }
            _strcat(lpCaption, TEXT(" Security Descriptor"));
            SetWindowText(hwndDlg, lpCaption);
            supHeapFree(lpCaption);
        }

        //
        // Set dialog icon.
        //
        hIcon = (HICON)LoadImage(g_WinObj.hInstance,
            MAKEINTRESOURCE(IDI_ICON_MAIN),
            IMAGE_ICON,
            32, 32,
            0);

        if (hIcon) {
            SendMessage(hwndDlg, WM_SETICON, (WPARAM)ICON_SMALL, (LPARAM)hIcon);
            SendMessage(hwndDlg, WM_SETICON, (WPARAM)ICON_BIG, (LPARAM)hIcon);
            SDViewContext->DialogIcon = hIcon;
        }

        SDViewContext->DialogWindow = hwndDlg;

        //
        // Dump object security information.
        //
        ntStatus = SdViewDumpObjectSecurity(SDViewContext);
        if (NT_SUCCESS(ntStatus)) {
            SetFocus(GetDlgItem(hwndDlg, IDC_SDVIEW_LIST));
        }
        else {
            //
            // On error - hide all child windows and show details of the error.
            //
            if (GetWindowRect(hwndDlg, &wndData.Rect)) {
                wndData.nCmdShow = SW_HIDE;
                EnumChildWindows(hwndDlg, supCallbackShowChildWindow, (LPARAM)&wndData);
            }
            ShowWindow(GetDlgItem(hwndDlg, ID_OBJECTDUMPERROR), SW_SHOW);
            lpCaption = supFormatNtError(ntStatus);
            if (lpCaption) {
                SetDlgItemText(hwndDlg, ID_OBJECTDUMPERROR, lpCaption);
                LocalFree((HLOCAL)lpCaption);
            }
        }
    }
}
