/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       PROPPROCESS.C
*
*  VERSION:     1.88
*
*  DATE:        29 Nov 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "propDlg.h"
#include "extras.h"

/*
* ProcessListCompareFunc
*
* Purpose:
*
* Process page listview comparer function.
*
*/
INT CALLBACK ProcessListCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lpContextParam
)
{
    INT       nResult = 0;
    LPWSTR    lpItem1 = NULL, lpItem2 = NULL, FirstToCompare, SecondToCompare;
    ULONG_PTR Value1, Value2;

    LPARAM lvColumnToSort;

    EXTRASCONTEXT* pDlgContext;

    pDlgContext = (EXTRASCONTEXT*)lpContextParam;
    if (pDlgContext == NULL)
        return 0;

    lvColumnToSort = (LPARAM)pDlgContext->lvColumnToSort;

    //
    // Sort Handle/GrantedAccess value column.
    //
    if ((lvColumnToSort == 2) || (lvColumnToSort == 3)) {
        return supGetMaxOfTwoU64FromHex(
            pDlgContext->ListView,
            lParam1,
            lParam2,
            lvColumnToSort,
            pDlgContext->bInverseSort);
    }


    lpItem1 = supGetItemText(
        pDlgContext->ListView,
        (INT)lParam1,
        (INT)lvColumnToSort,
        NULL);

    if (lpItem1 == NULL) //can't be 0 for this dialog
        goto Done;

    lpItem2 = supGetItemText(
        pDlgContext->ListView,
        (INT)lParam2,
        (INT)lvColumnToSort,
        NULL);

    if (lpItem2 == NULL) //can't be 0 for this dialog
        goto Done;

    switch (lvColumnToSort) {
    case 0:
        //
        // Name column.
        //
        if (pDlgContext->bInverseSort) {
            FirstToCompare = lpItem2;
            SecondToCompare = lpItem1;
        }
        else
        {
            FirstToCompare = lpItem1;
            SecondToCompare = lpItem2;
        }

        nResult = _strcmpi(FirstToCompare, SecondToCompare);
        break;

    case 1:
        //
        // Id column.
        //
        Value1 = strtou64(lpItem1);
        Value2 = strtou64(lpItem2);
        if (pDlgContext->bInverseSort)
            nResult = Value2 > Value1;
        else
            nResult = Value1 > Value2;
        break;

    default:
        break;
    }

Done:
    if (lpItem1) supHeapFree(lpItem1);
    if (lpItem2) supHeapFree(lpItem2);
    return nResult;
}

/*
* ProcessShowProperties
*
* Purpose:
*
* Query full target path and execute Windows shell properties dialog.
*
*/
VOID ProcessShowProperties(
    _In_ HWND hwndDlg,
    _In_ HWND hwndListView,
    _In_ INT iItem
)
{
    HANDLE          processId;
    PUNICODE_STRING pusFileName = NULL;

    WCHAR szBuffer[100];

    __try {
        //
        // Query process id.
        //
        szBuffer[0] = 0;
        supGetItemText2(hwndListView, iItem, 1, szBuffer, RTL_NUMBER_OF(szBuffer));
        processId = UlongToHandle(_strtoul(szBuffer));

        //
        // Query process image filename and show shell properties dialog.
        //
        if (NT_SUCCESS(supQueryProcessImageFileNameWin32(processId, &pusFileName))) {

            if (pusFileName->Buffer && pusFileName->Length)
                supShowProperties(hwndDlg, pusFileName->Buffer);

            ntsupHeapFree(pusFileName);
        }

    }
    __except (WOBJ_EXCEPTION_FILTER) {
        return;
    }
}

/*
* ProcessListHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for Process page listview.
*
*/
BOOL ProcessListHandleNotify(
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    INT     nImageIndex;
    EXTRASCONTEXT* pDlgContext;
    NMLISTVIEW* pListView = (NMLISTVIEW*)lParam;
    HWND hwndListView;

    if (pListView == NULL)
        return FALSE;

    if (pListView->hdr.idFrom != ID_PROCESSLIST)
        return FALSE;

    hwndListView = pListView->hdr.hwndFrom;

    switch (pListView->hdr.code) {

    case LVN_COLUMNCLICK:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            pDlgContext->bInverseSort = !pDlgContext->bInverseSort;
            pDlgContext->lvColumnToSort = pListView->iSubItem;

            ListView_SortItemsEx(
                hwndListView,
                &ProcessListCompareFunc,
                pDlgContext);

            if (pDlgContext->bInverseSort)
                nImageIndex = 1;
            else
                nImageIndex = 2;

            supUpdateLvColumnHeaderImage(
                hwndListView,
                pDlgContext->lvColumnCount,
                pDlgContext->lvColumnToSort,
                nImageIndex);
        }
        break;

    case NM_DBLCLK:

        ProcessShowProperties(
            hwndDlg,
            hwndListView,
            pListView->iItem);

        break;

    default:
        return FALSE;
    }

    return TRUE;
}

/*
* ProcessQueryInfo
*
* Purpose:
*
* Extracts icon resource from given process for use in listview and determines process WOW64 status.
*
*/
VOID ProcessQueryInfo(
    _In_ ULONG_PTR ProcessId,
    _Out_ HICON* pProcessIcon,
    _Out_ BOOL* pbIs32
)
{
    HANDLE          hProcess;
    NTSTATUS        ntStatus;

    HICON           hIcon = NULL;
    PUNICODE_STRING pusFileName = NULL;

    __try {
        *pProcessIcon = NULL;
        *pbIs32 = FALSE;

        ntStatus = supOpenProcess((HANDLE)ProcessId,
            PROCESS_QUERY_LIMITED_INFORMATION,
            &hProcess);

        if (NT_SUCCESS(ntStatus)) {

            //
            // Query if this is wow64 process.
            //
            *pbIs32 = supIsProcess32bit(hProcess);

            //
            // Query process icon, first query win32 imagefilename then parse image resources.
            //
            ntStatus = supQueryProcessInformation(hProcess,
                ProcessImageFileNameWin32,
                &pusFileName,
                NULL);

            if (NT_SUCCESS(ntStatus)) {
                if (pusFileName->Buffer && pusFileName->Length) {
                    hIcon = supGetMainIcon(pusFileName->Buffer, 16, 16);
                    if (hIcon) {
                        *pProcessIcon = hIcon;
                    }
                }
                ntsupHeapFree(pusFileName);
            }

            NtClose(hProcess);
        }

    }
    __except (WOBJ_EXCEPTION_FILTER) {
        return;
    }
}

/*
* ProcessListAddItem
*
* Purpose:
*
* Adds an item to the listview.
*
*/
VOID ProcessListAddItem(
    _In_ HWND hwndListView,
    _In_ HIMAGELIST ImageList,
    _In_ PVOID ProcessesList,
    _In_ PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX phti
)
{
    BOOL     bIsWow64;
    INT      nIndex, iImage;
    HICON    hIcon;
    LVITEM   lvitem;
    WCHAR    szBuffer[MAX_PATH * 2];

    if ((phti == NULL) || (ProcessesList == NULL)) {
        return;
    }

    //
    // Default image index.
    //
    iImage = 0;

    //
    // Set default process name as Unknown.
    //
    RtlSecureZeroMemory(&szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, T_Unknown);

    if (supQueryProcessName(
        phti->UniqueProcessId,
        ProcessesList,
        szBuffer,
        MAX_PATH))
    {
        //
        // Id exists, extract icon
        // Skip idle, system
        //
        if (phti->UniqueProcessId > 4) {

            hIcon = NULL;
            bIsWow64 = FALSE;
            ProcessQueryInfo(phti->UniqueProcessId, &hIcon, &bIsWow64);

            if (hIcon) {
                iImage = ImageList_ReplaceIcon(ImageList, -1, hIcon);
                DestroyIcon(hIcon);
            }
            if (bIsWow64) {
                _strcat(szBuffer, L"*32");
            }
            
        }
    }

    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));

    //
    // Process Name.
    //
    lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
    lvitem.iImage = iImage;
    lvitem.pszText = szBuffer;
    lvitem.iItem = MAXINT;
    nIndex = ListView_InsertItem(hwndListView, &lvitem);

    //
    // ProcessId.
    //
    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    u64tostr(phti->UniqueProcessId, szBuffer);
    lvitem.mask = LVIF_TEXT;
    lvitem.iSubItem = 1;
    lvitem.iItem = nIndex;
    ListView_SetItem(hwndListView, &lvitem);

    //
    // Handle Value.
    //
    _strcpy(szBuffer, L"0x");
    u64tohex(phti->HandleValue, _strend(szBuffer));
    lvitem.iSubItem = 2;
    ListView_SetItem(hwndListView, &lvitem);

    //
    // Handle GrantedAccess.
    //
    _strcpy(szBuffer, L"0x");
    ultohex(phti->GrantedAccess, _strend(szBuffer));
    lvitem.iSubItem = 3;
    ListView_SetItem(hwndListView, &lvitem);
}

/*
* ProcessEnumHandlesCallback
*
* Purpose:
*
* Handles enumeration callback.
*
*/
BOOL ProcessEnumHandlesCallback(
    _In_ SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* HandleEntry,
    _In_ PVOID UserContext
)
{
    PPS_HANDLE_DUMP_ENUM_CONTEXT userCtx = (PPS_HANDLE_DUMP_ENUM_CONTEXT)UserContext;

    //
    // Is this what we want?
    //
    if (HandleEntry->ObjectTypeIndex == userCtx->ObjectTypeIndex) {
        if ((ULONG_PTR)HandleEntry->Object == userCtx->ObjectAddress) {

            //
            // Decode and add information to the list.
            //
            ProcessListAddItem(userCtx->ListView,
                userCtx->ImageList,
                userCtx->ProcessList,
                HandleEntry);
        }
    }

    return FALSE;
}

/*
* ProcessListSetInfo
*
* Purpose:
*
* Query information and fill listview.
* Called each time when page became visible.
*
*/
VOID ProcessListSetInfo(
    _In_ HWND hwndDlg,
    _In_ PROP_OBJECT_INFO* Context,
    _In_ EXTRASCONTEXT* pDlgContext
)
{
    BOOL                            bObjectFound = FALSE;
    USHORT                          ObjectTypeIndex = 0;
    ULONG_PTR                       ObjectAddress = 0;
    ACCESS_MASK                     DesiredAccess;
    PVOID                           ProcessList = NULL;
    HANDLE                          hObject = NULL;
    HICON                           hIcon;
    PSYSTEM_HANDLE_INFORMATION_EX   pHandles = NULL;

    PS_HANDLE_DUMP_ENUM_CONTEXT     enumContext;

    VALIDATE_PROP_CONTEXT(Context);

    //empty process list images
    ImageList_RemoveAll(pDlgContext->ImageList);

    //empty process list
    ListView_DeleteAllItems(GetDlgItem(hwndDlg, ID_PROCESSLIST));

    //set default app icon
    hIcon = LoadIcon(NULL, IDI_APPLICATION);

    if (hIcon) {
        ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hIcon);
        DestroyIcon(hIcon);
    }

    //sort image up
    hIcon = (HICON)LoadImage(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDI_ICON_SORTUP), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);

    if (hIcon) {
        ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hIcon);
        DestroyIcon(hIcon);
    }

    //sort image down
    hIcon = (HICON)LoadImage(g_WinObj.hInstance,
        MAKEINTRESOURCE(IDI_ICON_SORTDOWN), IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);

    if (hIcon) {
        ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hIcon);
        DestroyIcon(hIcon);
    }

    //
    // Check if additional info is available.
    //
    if (Context->ObjectInfo.ObjectAddress != 0) {

        ObjectAddress = Context->ObjectInfo.ObjectAddress;

        ObjectTypeIndex = ObDecodeTypeIndex((PVOID)ObjectAddress,
            Context->ObjectInfo.ObjectHeader.TypeIndex);

        bObjectFound = TRUE;
    }

    do {
        //
        // When object address is unknown, open object and query it address.
        // This DesiredAccess flag is used to open currently viewed object.
        //
        if (ObjectAddress == 0) {

            DesiredAccess = READ_CONTROL;
            bObjectFound = FALSE;

            //
            // Open temporary object handle to query object address.
            //
            if (propOpenCurrentObject(Context, &hObject, DesiredAccess)) {

                pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation, NULL);
                if (pHandles) {

                    //
                    // Find our handle object by handle value.
                    //
                    bObjectFound = supQueryObjectFromHandleEx(pHandles,
                        hObject,
                        &ObjectAddress,
                        &ObjectTypeIndex);

                    supHeapFree(pHandles);
                }

                supCloseObjectFromContext(Context, hObject);
            }

        }

        //
        // Nothing to compare.
        //
        if (bObjectFound == FALSE)
            break;

        //
        // Take process and handles snapshot.
        //
        ProcessList = supGetSystemInfo(SystemProcessInformation, NULL);
        if (ProcessList == NULL)
            break;

        pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation, NULL);
        if (pHandles) {

            //
            // Find any handles with the same object address and object type.
            //
            enumContext.ImageList = pDlgContext->ImageList;
            enumContext.ListView = pDlgContext->ListView;
            enumContext.ProcessList = ProcessList;
            enumContext.ObjectAddress = ObjectAddress;
            enumContext.ObjectTypeIndex = ObjectTypeIndex;

            supEnumHandleDump(pHandles,
                (PENUMERATE_HANDLE_DUMP_CALLBACK)ProcessEnumHandlesCallback,
                &enumContext);

            supHeapFree(pHandles);
            pHandles = NULL;
        }

    } while (FALSE);

    //
    // Cleanup.
    //
    if (pHandles) {
        supHeapFree(pHandles);
    }
    if (ProcessList) {
        supHeapFree(ProcessList);
    }

    //
    // Show/hide notification text.
    //
    ShowWindow(GetDlgItem(hwndDlg, ID_PROCESSLISTNOALL), (ObjectAddress == 0) ? SW_SHOW : SW_HIDE);
}

/*
* ProcessListCreate
*
* Purpose:
*
* Initialize listview for process list.
* Called once.
*
*/
VOID ProcessListCreate(
    _In_ HWND hwndDlg,
    _In_ EXTRASCONTEXT* pDlgContext
)
{
    pDlgContext->ListView = GetDlgItem(hwndDlg, ID_PROCESSLIST);
    if (pDlgContext->ListView == NULL)
        return;

    pDlgContext->ImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 32, 8);
    if (pDlgContext->ImageList) {
        ListView_SetImageList(pDlgContext->ListView, pDlgContext->ImageList, LVSIL_SMALL);
    }

    ListView_SetExtendedListViewStyle(
        pDlgContext->ListView,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);

    SetWindowTheme(pDlgContext->ListView, TEXT("Explorer"), NULL);

    //
    // Add listview columns.
    //

    supAddListViewColumn(pDlgContext->ListView, 0, 0, 0,
        2,
        LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
        TEXT("Process"),
        160);

    supAddListViewColumn(pDlgContext->ListView, 1, 1, 1,
        I_IMAGENONE,
        LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
        TEXT("ID"),
        60);

    supAddListViewColumn(pDlgContext->ListView, 2, 2, 2,
        I_IMAGENONE,
        LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
        TEXT("Handle"),
        130);

    supAddListViewColumn(pDlgContext->ListView, 3, 3, 3,
        I_IMAGENONE,
        LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
        TEXT("Access"),
        80);

    pDlgContext->lvColumnCount = PROCESSLIST_COLUMN_COUNT;
}

/*
* ProcessHandlePopupMenu
*
* Purpose:
*
* Process list popup construction
*
*/
VOID ProcessHandlePopupMenu(
    _In_ HWND hwndDlg
)
{
    POINT pt1;
    HMENU hMenu;

    if (GetCursorPos(&pt1) == FALSE)
        return;

    hMenu = CreatePopupMenu();
    if (hMenu) {
        InsertMenu(hMenu, 0, MF_BYCOMMAND, ID_OBJECT_COPY, T_COPYTEXTROW);
        TrackPopupMenu(hMenu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, pt1.x, pt1.y, 0, hwndDlg, NULL);
        DestroyMenu(hMenu);
    }
}

/*
* ProcessCopyText
*
* Purpose:
*
* Copy selected list view row to the clipboard.
*
*/
VOID ProcessCopyText(
    _In_ HWND hwndList,
    _In_ INT lvComlumnCount
)
{
    INT     nSelection, i;
    SIZE_T  cbText, sz;
    LPWSTR  lpText, lpItemText[4];

    if (ListView_GetSelectedCount(hwndList) == 0) {
        return;
    }

    nSelection = ListView_GetSelectionMark(hwndList);
    if (nSelection == -1) {
        return;
    }

    __try {
        cbText = 0;
        for (i = 0; i < lvComlumnCount; i++) {
            sz = 0;
            lpItemText[i] = supGetItemText(hwndList, nSelection, i, &sz);
            cbText += sz;
        }

        cbText += (lvComlumnCount * sizeof(WCHAR)) + sizeof(UNICODE_NULL);
        lpText = (LPWSTR)supHeapAlloc(cbText);
        if (lpText) {

            for (i = 0; i < lvComlumnCount; i++) {
                if (lpItemText[i]) {
                    _strcat(lpText, lpItemText[i]);
                    if (i != 3) {
                        _strcat(lpText, L" ");
                    }
                }
            }
            supClipboardCopy(lpText, cbText);
            supHeapFree(lpText);
        }
        for (i = 0; i < lvComlumnCount; i++) {
            if (lpItemText[i] != NULL) {
                supHeapFree(lpItemText[i]);
            }
        }
    }
    __except (WOBJ_EXCEPTION_FILTER) {
        return;
    }
}

/*
* ProcessListDialogProc
*
* Purpose:
*
* Process list page for various object types.
*
* WM_INITDIALOG - Initialize listview, set window prop with context,
* collect processes info and fill list.
*
* WM_NOTIFY - Handle list view notifications.
*
* WM_DESTROY - Free image list and remove window prop.
*
* WM_CONTEXTMENU - Handle popup menu.
*
*/
INT_PTR CALLBACK ProcessListDialogProc(
    _In_  HWND hwndDlg,
    _In_  UINT uMsg,
    _In_  WPARAM wParam,
    _In_  LPARAM lParam
)
{
    PROPSHEETPAGE* pSheet = NULL;
    PROP_OBJECT_INFO* Context = NULL;
    EXTRASCONTEXT* pDlgContext = NULL;

    switch (uMsg) {

    case WM_CONTEXTMENU:
        ProcessHandlePopupMenu(hwndDlg);
        break;

    case WM_COMMAND:

        if (GET_WM_COMMAND_ID(wParam, lParam) == ID_OBJECT_COPY) {
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if (pDlgContext) {
                ProcessCopyText(pDlgContext->ListView, pDlgContext->lvColumnCount);
            }
        }
        break;

    case WM_NOTIFY:
        return ProcessListHandleNotify(hwndDlg, lParam);

    case WM_DESTROY:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            if (pDlgContext->ImageList) {
                ImageList_Destroy(pDlgContext->ImageList);
            }
            supHeapFree(pDlgContext);
        }
        RemoveProp(hwndDlg, T_PROPCONTEXT);
        RemoveProp(hwndDlg, T_DLGCONTEXT);
        break;

    case WM_INITDIALOG:

        pSheet = (PROPSHEETPAGE*)lParam;
        if (pSheet) {
            Context = (PROP_OBJECT_INFO*)pSheet->lParam;
            SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)Context);

            pDlgContext = (EXTRASCONTEXT*)supHeapAlloc(sizeof(EXTRASCONTEXT));
            if (pDlgContext) {
                SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)pDlgContext);

                ProcessListCreate(hwndDlg, pDlgContext);
                if (pDlgContext->ListView) {

                    ProcessListSetInfo(hwndDlg, Context, pDlgContext);

                    ListView_SortItemsEx(
                        pDlgContext->ListView,
                        &ProcessListCompareFunc,
                        pDlgContext);
                }
            }
        }
        break;

    default:
        return FALSE;
    }

    return TRUE;
}
