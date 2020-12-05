/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       SDVIEWDLG.C
*
*  VERSION:     1.88
*
*  DATE:        04 Dec 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "sdviewDlg.h"

typedef VOID(CALLBACK* pfnSidOutputCallback)(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ LPWSTR Information
    );

typedef VOID(CALLBACK* pfnAceOutputCallback)(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ LPWSTR lpAceType,
    _In_ LPWSTR lpAceFlags,
    _In_ LPWSTR lpAccessMask,
    _In_opt_ LPWSTR lpDomain,
    _In_opt_ LPWSTR lpName,
    _In_ LPWSTR lpSidNameUse,
    _In_ PUNICODE_STRING SidString
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

VOID CALLBACK OutputSidCallback(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ LPWSTR SidInformation
)
{
    SetDlgItemText(Context->DialogWindow, IDC_SDVIEW_OWNER, SidInformation);
}

VOID CALLBACK OutputAclEntryCallback(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ LPWSTR lpAceType,
    _In_ LPWSTR lpAceFlags,
    _In_ LPWSTR lpAccessMask,
    _In_opt_ LPWSTR lpDomain,
    _In_opt_ LPWSTR lpName,
    _In_ LPWSTR lpSidNameUse,
    _In_ PUNICODE_STRING SidString
)
{
    INT lvItemIndex;
    HWND hwndList = GetDlgItem(Context->DialogWindow, IDC_SDVIEW_LIST);

    LVITEM lvItem;
    WCHAR szBuffer[1040];


    RtlSecureZeroMemory(&lvItem, sizeof(lvItem));

    //
    // Ace type.
    //
    lvItem.mask = LVIF_TEXT;
    lvItem.iItem = MAXINT;
    lvItem.iImage = I_IMAGENONE;
    lvItem.pszText = lpAceType;
    lvItem.cchTextMax = (INT)_strlen(lpAceType);
    lvItemIndex = ListView_InsertItem(hwndList, &lvItem);

    //
    // Ace flags.
    //
    lvItem.pszText = lpAceFlags;
    lvItem.cchTextMax = (INT)_strlen(lpAceFlags);
    lvItem.iItem = lvItemIndex;
    ++lvItem.iSubItem;
    ListView_SetItem(hwndList, &lvItem);

    //
    // Acess mask.
    //
    lvItem.pszText = lpAccessMask;
    lvItem.cchTextMax = (INT)_strlen(lpAccessMask);
    ++lvItem.iSubItem;
    ListView_SetItem(hwndList, &lvItem);

    //
    // SID.
    //
    RtlStringCchPrintfSecure(szBuffer,
        RTL_NUMBER_OF(szBuffer),
        L"%wZ",
        SidString);

    lvItem.pszText = szBuffer;
    lvItem.cchTextMax = (INT)_strlen(szBuffer);
    ++lvItem.iSubItem;
    ListView_SetItem(hwndList, &lvItem);

    //
    // Domain and Name
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    if (lpDomain) {
        _strcpy(szBuffer, lpDomain);
        if (lpName) {
            _strcat(szBuffer, TEXT("\\"));
            _strcat(szBuffer, lpName);
        }
    }
    else {
        if (lpName)
            _strcpy(szBuffer, lpName);
    }

    lvItem.pszText = szBuffer;
    lvItem.cchTextMax = (INT)_strlen(szBuffer);
    ++lvItem.iSubItem;
    ListView_SetItem(hwndList, &lvItem);

    //
    // Alias.
    //
    lvItem.pszText = lpSidNameUse;
    lvItem.cchTextMax = (INT)_strlen(lpSidNameUse);
    ++lvItem.iSubItem;
    ListView_SetItem(hwndList, &lvItem);
}

/*
* SdViewDumpAceList
*
* Purpose:
*
* Output ACE list members.
*
*/
VOID SdViewDumpAceList(
    _In_ SDVIEW_CONTEXT* Context,
    _In_ ULONG AceCount,
    _In_ PVOID FirstAce,
    _In_ LSA_HANDLE PolicyHandle,
    _In_ pfnAceOutputCallback OutputCallback
)
{
    ULONG domainIndex, nCount, domainsEntries = 0;
    NTSTATUS ntStatus;
    BOOL bDomainNamePresent = FALSE, bNamePresent = FALSE;

    PLSA_TRANSLATED_NAME translatedNames = NULL, pNames = NULL;
    PLSA_REFERENCED_DOMAIN_LIST referencedDomains = NULL;
    PUNICODE_STRING pusDomainName, pusName;
    PSID* lookupSids;
    PSID aceSid;
    ULONG sidCount = 0;
    ACCESS_MASK accessMask;

    UNICODE_STRING stringSid, usEmpty;

    SID_NAME_USE sidNameUse;

    WCHAR szDomain[512], szName[512];
    WCHAR szAccessMask[32], szAceType[32], szAceFlags[32];
    LPWSTR lpAceType;

    union {
        PBYTE ListRef;
        PACE_HEADER Header;
        PACCESS_ALLOWED_ACE AccessAllowed;
    } aceList;

    aceList.ListRef = (PBYTE)FirstAce;

    //
    // Allocate array of sids for LsaLookupSids.
    //
    lookupSids = (PSID*)supHeapAlloc(AceCount * sizeof(PSID));
    if (lookupSids == NULL)
        return;

    __try {

        //
        // Fill sids array for LsaLookupSids.
        //
        nCount = AceCount;

        do {

            aceSid = supGetSidFromAce(aceList.Header);

            if (RtlValidSid(aceSid)) {
                lookupSids[sidCount++] = aceSid;
            }

            aceList.ListRef += aceList.Header->AceSize;

        } while (--nCount);

        //
        // Lookup sids.
        //
        ntStatus = LsaLookupSids(PolicyHandle,
            sidCount,
            lookupSids,
            &referencedDomains,
            &translatedNames);

        if (NT_SUCCESS(ntStatus)) {

            pNames = translatedNames;
            domainsEntries = referencedDomains->Entries;

        }

        aceList.ListRef = (PBYTE)FirstAce;
        nCount = AceCount;

        RtlInitEmptyUnicodeString(&stringSid, NULL, 0);
        RtlInitEmptyUnicodeString(&usEmpty, NULL, 0);

        //
        // List aces.
        //

        do {

            aceSid = supGetSidFromAce(aceList.Header);
            if (!RtlValidSid(aceSid)) {
                continue;
            }

            //
            // Convert SID to string, on failure zero result so RtlFreeUnicodeString won't fuckup.
            //
            if (!NT_SUCCESS(RtlConvertSidToUnicodeString(&stringSid,
                aceSid,
                TRUE)))
            {
                stringSid.Buffer = NULL;
                stringSid.Length = 0;
            }

            sidNameUse = SidTypeUnknown;
            pusDomainName = &usEmpty;
            pusName = &usEmpty;

            //
            // Link domain, name and sid name use.
            //

            if (pNames) {

                domainIndex = pNames->DomainIndex;
                if (domainIndex < domainsEntries)
                    pusDomainName = &referencedDomains->Domains[domainIndex].Name;

                pusName = &pNames->Name;
                sidNameUse = pNames->Use;
                pNames++;

            }

            bDomainNamePresent = (pusDomainName->Length > 0);
            bNamePresent = (pusName->Length > 0);

            accessMask = aceList.AccessAllowed->Mask;

            szAccessMask[0] = L'0';
            szAccessMask[1] = L'x';
            szAccessMask[2] = 0;
            ultohex((ULONG)accessMask, &szAccessMask[2]);

            szAceFlags[0] = L'0';
            szAceFlags[1] = L'x';
            szAceFlags[2] = 0;
            ultohex((ULONG)aceList.Header->AceFlags, &szAceFlags[2]);

            switch (aceList.Header->AceType) {

            case ACCESS_ALLOWED_ACE_TYPE:
                lpAceType = L"Allowed";
                break;

            case ACCESS_DENIED_ACE_TYPE:
                lpAceType = L"Denied";
                break;

            case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
                lpAceType = L"Mandatory";
                szAccessMask[0] = accessMask & SYSTEM_MANDATORY_LABEL_NO_READ_UP ? L'R' : L' ';
                szAccessMask[1] = accessMask & SYSTEM_MANDATORY_LABEL_NO_WRITE_UP ? L'W' : L' ';
                szAccessMask[2] = accessMask & SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP ? L'E' : L' ';
                szAccessMask[3] = 0;
                break;

            case SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE:
                lpAceType = L"TrustLabel";
                break;

            case SYSTEM_ACCESS_FILTER_ACE_TYPE:
                lpAceType = L"AccessFilter";
                break;

            default:
                //
                // Irrelevant, report as is.
                //
                szAceType[0] = L'0';
                szAceType[1] = L'x';
                szAceType[2] = 0;
                ultohex((ULONG)aceList.Header->AceType, &szAceType[2]);
                lpAceType = (LPWSTR)&szAceType;
                break;
            }

            //
            // Domain and name.
            //
            RtlSecureZeroMemory(&szDomain, sizeof(szDomain));
            szDomain[0] = 0;
            RtlSecureZeroMemory(&szName, sizeof(szName));
            szName[0] = 0;

            switch (sidNameUse) {
            case SidTypeInvalid:
            case SidTypeUnknown:
                //
                // Invalid or unknown, skip domain and name.
                //
                break;

            default:

                if (bNamePresent) {

                    RtlStringCchPrintfSecure(szName,
                        RTL_NUMBER_OF(szName),
                        L"%wZ",
                        pusName);

                }

                if (bDomainNamePresent) {

                    RtlStringCchPrintfSecure(szDomain,
                        RTL_NUMBER_OF(szDomain),
                        L"%wZ",
                        pusDomainName);

                }

                break;
            }

            OutputCallback(Context,
                lpAceType,
                szAceFlags,
                szAccessMask,
                bDomainNamePresent ? szDomain : NULL,
                bNamePresent ? szName : NULL,
                supGetSidNameUse(sidNameUse),
                &stringSid);

            RtlFreeUnicodeString(&stringSid);

        } while (aceList.ListRef += aceList.Header->AceSize, --nCount);

    }
    __finally {
        supHeapFree(lookupSids);
        if (referencedDomains) LsaFreeMemory(referencedDomains);
        if (translatedNames) LsaFreeMemory(translatedNames);
    }

}

/*
* SdViewDumpAcl
*
* Purpose:
*
* Output ACL information.
*
*/
VOID SdViewDumpAcl(
    _In_ SDVIEW_CONTEXT* Context,
    _In_opt_ PACL Acl,
    _In_ LSA_HANDLE PolicyHandle,
    _In_ pfnAceOutputCallback OutputCallback
)
{
    PVOID firstAce = NULL;

    if (Acl == NULL) {
        return;
    }

    if (Acl->AceCount == 0) {
        return;
    }

    if (NT_SUCCESS(RtlGetAce(Acl, 0, &firstAce))) {

        SdViewDumpAceList(Context,
            Acl->AceCount,
            firstAce,
            PolicyHandle,
            OutputCallback);

    }
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
    _In_ LSA_HANDLE PolicyHandle,
    _In_ pfnSidOutputCallback OutputCallback
)
{
    ULONG domainIndex, domainsEntries;
    NTSTATUS ntStatus;
    PLSA_TRANSLATED_NAME translatedNames = NULL, pNames;
    PLSA_REFERENCED_DOMAIN_LIST referencedDomains = NULL;
    PUNICODE_STRING pusDomainName, pusName;
    LPWSTR pSidNameUseString = NULL;

    UNICODE_STRING stringSid, usEmpty;

    SID_NAME_USE sidNameUse;

    WCHAR szBuffer[512];

    //
    // Do we have anything to show?
    //
    if (!RtlValidSid(Sid))
        return;

    __try {

        pNames = NULL;
        domainsEntries = 0;

        ntStatus = LsaLookupSids(PolicyHandle,
            1,
            &Sid,
            &referencedDomains,
            &translatedNames);

        if (NT_SUCCESS(ntStatus)) {
            pNames = translatedNames;
            domainsEntries = referencedDomains->Entries;
        }

        RtlInitEmptyUnicodeString(&stringSid, NULL, 0);
        RtlInitEmptyUnicodeString(&usEmpty, NULL, 0);

        //
        // Convert SID to string, on failure zero result so RtlFreeUnicodeString won't fuckup.
        //
        if (!NT_SUCCESS(RtlConvertSidToUnicodeString(&stringSid,
            Sid,
            TRUE)))
        {
            stringSid.Buffer = NULL;
            stringSid.Length = 0;
        }

        sidNameUse = SidTypeUnknown;
        pusDomainName = &usEmpty;
        pusName = &usEmpty;

        //
        // Link domain, name and sid name use.
        //
        if (pNames) {

            domainIndex = pNames->DomainIndex;
            if (domainIndex < domainsEntries)
                pusDomainName = &referencedDomains->Domains[domainIndex].Name;

            pusName = &pNames->Name;
            sidNameUse = pNames->Use;
            pNames++;

        }

        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        pSidNameUseString = supGetSidNameUse(sidNameUse);

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

        RtlFreeUnicodeString(&stringSid);
        OutputCallback(Context, szBuffer);

    }
    __finally {
        if (referencedDomains) LsaFreeMemory(referencedDomains);
        if (translatedNames) LsaFreeMemory(translatedNames);
    }
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
            NULL);

        if (!NT_SUCCESS(ntStatus))
            __leave;


        pOwnerSid = NULL;
        ntQueryStatus = RtlGetOwnerSecurityDescriptor(pSD, &pOwnerSid, &bDefaulted);
        if (NT_SUCCESS(ntQueryStatus)) {

            SdViewDumpSid(Context, pOwnerSid, hPolicy, &OutputSidCallback);

        }

        pAcl = NULL;
        ntQueryStatus = RtlGetDaclSecurityDescriptor(pSD, &bPresent, &pAcl, &bDefaulted);
        if (NT_SUCCESS(ntQueryStatus)) {

            SdViewDumpAcl(Context, pAcl, hPolicy, &OutputAclEntryCallback);

        }

        pAcl = NULL;
        ntQueryStatus = RtlGetSaclSecurityDescriptor(pSD, &bPresent, &pAcl, &bDefaulted);
        if (NT_SUCCESS(ntQueryStatus)) {

            SdViewDumpAcl(Context, pAcl, hPolicy, &OutputAclEntryCallback);

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
    struct LVColumns {
        LPWSTR Name;
        INT Width;
        INT Format;
    } columnData[] =
    {
        { L"Type", 80, LVCFMT_CENTER },
        { L"Flags", 80, LVCFMT_CENTER },
        { L"AccessMask", 120, LVCFMT_CENTER },
        { L"SID", 120, LVCFMT_LEFT },
        { L"Domain\\Name", 200, LVCFMT_LEFT },
        { L"UseName", 120, LVCFMT_LEFT }
    };

    INT i;
    HWND aclList = GetDlgItem(hwndDlg, IDC_SDVIEW_LIST);
    HWND sidOwner = GetDlgItem(hwndDlg, IDC_SDVIEW_OWNER);
    DWORD dwStyle = LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP;

    if (g_WinObj.ListViewDisplayGrid)
        dwStyle |= LVS_EX_GRIDLINES;

    ListView_SetExtendedListViewStyle(aclList, dwStyle);

    // SendMessage(aclList, LVM_ENABLEGROUPVIEW, 1, 0);

    SetWindowTheme(aclList, TEXT("Explorer"), NULL);

    for (i = 0; i < RTL_NUMBER_OF(columnData); i++) {

        supAddListViewColumn(aclList, i, i, i,
            I_IMAGENONE,
            columnData[i].Format,
            columnData[i].Name,
            columnData[i].Width);
    }

    SetWindowText(sidOwner, T_EmptyString);
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
    _In_ LPWSTR ObjectName,
    _In_ WOBJ_OBJECT_TYPE ObjectType
)
{
    HICON hIcon;
    HWND hwndDlg;
    NTSTATUS ntStatus;
    SDVIEW_CONTEXT* SDViewContext;

    LPWSTR lpText;
//    SIZE_T nLen;

    ENUMCHILDWNDDATA wndData;

    if (ObjectDirectory == NULL || ObjectName == NULL)
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
        SetWindowText(hwndDlg, TEXT("Security Descriptor"));

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
            lpText = supFormatNtError(ntStatus);
            if (lpText) {
                SetDlgItemText(hwndDlg, ID_OBJECTDUMPERROR, lpText);
                LocalFree((HLOCAL)lpText);
            }
        }
    }
}
