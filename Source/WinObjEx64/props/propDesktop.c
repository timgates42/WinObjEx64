/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2021
*
*  TITLE:       PROPDESKTOP.C
*
*  VERSION:     1.88
*
*  DATE:        05 Dec 2020
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

//number of columns, revise this unit code after any change to this number
#define DESKTOPLIST_COLUMN_COUNT 3

typedef struct _DLG_ENUM_CALLBACK_CONTEXT {
    PROP_OBJECT_INFO* ObjectContext;
    EXTRASCONTEXT* DialogContext;
} DLG_ENUM_CALLBACK_CONTEXT, * PDLG_ENUM_CALLBACK_CONTEXT;

/*
* DesktopListEnumProc
*
* Purpose:
*
* EnumDesktops callback.
*
*/
BOOL CALLBACK DesktopListEnumProc(
    _In_ LPWSTR lpszDesktop,
    _In_ LPARAM lParam
)
{
    BOOL   bSucc;
    INT	   nIndex;
    DWORD  bytesNeeded, dwDesktopHeapSize;
    LPWSTR lpName, StringSid;
    PSID   pSID;
    SIZE_T sz;
    HDESK  hDesktop;
    LVITEM lvitem;
    WCHAR  szBuffer[MAX_PATH];

    DLG_ENUM_CALLBACK_CONTEXT* enumParam = (DLG_ENUM_CALLBACK_CONTEXT*)lParam;
    if (enumParam == NULL) {
        return FALSE;
    }

    // Desktop\\Object+0
    sz = (3 + _strlen(lpszDesktop) + _strlen(enumParam->ObjectContext->lpObjectName)) * sizeof(WCHAR);
    lpName = (LPWSTR)supHeapAlloc(sz);
    if (lpName == NULL)
        return 0;

    _strcpy(lpName, enumParam->ObjectContext->lpObjectName);
    _strcat(lpName, TEXT("\\"));
    _strcat(lpName, lpszDesktop);

    //Name
    RtlSecureZeroMemory(&lvitem, sizeof(lvitem));
    lvitem.mask = LVIF_TEXT | LVIF_IMAGE;
    lvitem.pszText = lpName;
    lvitem.iItem = MAXINT;
    nIndex = ListView_InsertItem(enumParam->DialogContext->ListView, &lvitem);

    supHeapFree(lpName);

    //
    // Query desktop objects information.
    //
    bSucc = FALSE;
    StringSid = NULL;
    hDesktop = OpenDesktop(lpszDesktop, 0, FALSE, DESKTOP_READOBJECTS);
    if (hDesktop) {

        //
        // Query SID.
        //
        bytesNeeded = 0;
        GetUserObjectInformation(hDesktop, UOI_USER_SID, NULL, 0, &bytesNeeded);

        //
        // User associated with desktop present, query sid.
        //
        if (bytesNeeded) {
            //
            // Allocate memory for sid.
            //
            pSID = supHeapAlloc(bytesNeeded);
            if (pSID) {
                if (GetUserObjectInformation(hDesktop,
                    UOI_USER_SID, pSID, bytesNeeded, &bytesNeeded))
                {
                    bSucc = ConvertSidToStringSid(pSID, &StringSid);
                }
                supHeapFree(pSID);
            }
        }

        //
        // Add SID string to the list.
        //
        if (bSucc && StringSid) {
            lvitem.mask = LVIF_TEXT;
            lvitem.iSubItem = 1;
            lvitem.pszText = StringSid;
            lvitem.iItem = nIndex;
            ListView_SetItem(enumParam->DialogContext->ListView, &lvitem);
            LocalFree(StringSid);
        }

        //
        // Add Desktop Heap Size, returned in KBytes.
        //
        dwDesktopHeapSize = 0;
        if (GetUserObjectInformation(hDesktop,
            UOI_HEAPSIZE,
            &dwDesktopHeapSize,
            sizeof(dwDesktopHeapSize),
            &bytesNeeded))
        {
            if (dwDesktopHeapSize) {
                RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
                ultostr(dwDesktopHeapSize / 1024, szBuffer);
                _strcat(szBuffer, TEXT(" Mb"));
                lvitem.pszText = szBuffer;
            }
            else {
                lvitem.pszText = T_EmptyString;
            }

            lvitem.mask = LVIF_TEXT;
            lvitem.iSubItem = 2;
            lvitem.iItem = nIndex;
            ListView_SetItem(enumParam->DialogContext->ListView, &lvitem);
        }
        CloseDesktop(hDesktop);
    }
    return TRUE;
}

/*
* DesktopListSetInfo
*
* Purpose:
*
* Query information and fill listview.
* Called each time when page became visible.
*
*/
VOID DesktopListSetInfo(
    _In_ HWND hwndDlg,
    _In_ PROP_OBJECT_INFO* Context,
    _In_ EXTRASCONTEXT* pDlgContext
)
{
    BOOL    bResult = FALSE;
    HWINSTA hObject;

    DLG_ENUM_CALLBACK_CONTEXT enumParam;

    ListView_DeleteAllItems(pDlgContext->ListView);

    hObject = supOpenWindowStationFromContext(Context, FALSE, WINSTA_ENUMDESKTOPS);
    if (hObject) {

        enumParam.ObjectContext = Context;
        enumParam.DialogContext = pDlgContext;

        EnumDesktops(hObject, DesktopListEnumProc, (LPARAM)&enumParam);

        CloseWindowStation(hObject);
        bResult = TRUE;
    }
    ShowWindow(GetDlgItem(hwndDlg, ID_DESKTOPSNOTALL), (bResult == FALSE) ? SW_SHOW : SW_HIDE);
}

/*
* DesktopListCreate
*
* Purpose:
*
* Initialize listview for desktop list.
* Called once.
*
*/
VOID DesktopListCreate(
    _In_ HWND hwndDlg,
    _In_ EXTRASCONTEXT* pDlgContext
)
{
    HICON hImage;

    pDlgContext->ListView = GetDlgItem(hwndDlg, ID_DESKTOPSLIST);
    if (pDlgContext->ListView == NULL)
        return;

    pDlgContext->ImageList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 8, 8);
    if (pDlgContext->ImageList) {

        //desktop image
        hImage = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_DESKTOP),
            IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);

        if (hImage) {
            ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hImage);
            DestroyIcon(hImage);
        }

        //sort images
        hImage = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_SORTUP),
            IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);

        if (hImage) {
            ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hImage);
            DestroyIcon(hImage);
        }
        hImage = (HICON)LoadImage(g_WinObj.hInstance, MAKEINTRESOURCE(IDI_ICON_SORTDOWN),
            IMAGE_ICON, 0, 0, LR_DEFAULTCOLOR);

        if (hImage) {
            ImageList_ReplaceIcon(pDlgContext->ImageList, -1, hImage);
            DestroyIcon(hImage);
        }

    }

    //
    // Set listview imagelist, style flags and theme.
    //
    supSetListViewSettings(pDlgContext->ListView,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP,
        FALSE,
        TRUE,
        pDlgContext->ImageList,
        LVSIL_SMALL);

    //
    // Add listview columns.
    //
    supAddListViewColumn(pDlgContext->ListView, 0, 0, 0,
        2,
        LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
        TEXT("Name"), 200);

    supAddListViewColumn(pDlgContext->ListView, 1, 1, 1,
        I_IMAGENONE,
        LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
        TEXT("SID"), 100);

    supAddListViewColumn(pDlgContext->ListView, 2, 2, 2,
        I_IMAGENONE,
        LVCFMT_LEFT | LVCFMT_BITMAP_ON_RIGHT,
        TEXT("Heap Size"), 100);

    pDlgContext->lvColumnCount = DESKTOPLIST_COLUMN_COUNT;
}

/*
* DesktopListCompareFunc
*
* Purpose:
*
* Desktop page listview comparer function.
*
*/
INT CALLBACK DesktopListCompareFunc(
    _In_ LPARAM lParam1,
    _In_ LPARAM lParam2,
    _In_ LPARAM lpContextParam
)
{
    EXTRASCONTEXT* pDlgContext;

    pDlgContext = (EXTRASCONTEXT*)lpContextParam;
    if (pDlgContext == NULL)
        return 0;

    return supListViewBaseComparer(pDlgContext->ListView,
        pDlgContext->bInverseSort,
        lParam1,
        lParam2,
        pDlgContext->lvColumnToSort);
}

/*
* DesktopListShowProperties
*
* Purpose:
*
* Desktop properies double click handler.
*
*/
VOID DesktopListShowProperties(
    _In_ HWND hwndDlg
)
{
    EXTRASCONTEXT* pDlgContext;
    SIZE_T ItemTextSize, i, l;
    LPWSTR lpName, lpItemText;

    PROP_DIALOG_CREATE_SETTINGS propSettings;

    //
    // Allow only one dialog at same time.
    //
    ENSURE_DIALOG_UNIQUE(g_DesktopPropWindow);

    //
    // A very basic support for this type.
    // Desktop described by win32k PDESKTOP structure which is totally undocumented.
    //
    pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
    if (pDlgContext) {

        ItemTextSize = 0;
        lpItemText = supGetItemText(
            pDlgContext->ListView,
            ListView_GetSelectionMark(pDlgContext->ListView),
            0,
            &ItemTextSize);

        if (lpItemText) {
            l = 0;
            for (i = 0; i < ItemTextSize / sizeof(WCHAR); i++)
                if (lpItemText[i] == L'\\')
                    l = i + 1;
            lpName = &lpItemText[l];

            RtlSecureZeroMemory(&propSettings, sizeof(propSettings));
            propSettings.hwndParent = hwndDlg;
            propSettings.lpObjectName = lpName;
            propSettings.lpObjectType = OBTYPE_NAME_DESKTOP;

            propCreateDialog(&propSettings);

            supHeapFree(lpItemText);
        }
    }
}

/*
* DesktopListHandleNotify
*
* Purpose:
*
* WM_NOTIFY processing for Desktop page listview.
*
*/
BOOL DesktopListHandleNotify(
    _In_ HWND hwndDlg,
    _In_ LPARAM lParam
)
{
    INT nImageIndex;
    LPNMLISTVIEW nhdr = (LPNMLISTVIEW)lParam;
    EXTRASCONTEXT* pDlgContext;

    if (nhdr == NULL) {
        return FALSE;
    }

    if (nhdr->hdr.idFrom != ID_DESKTOPSLIST) {
        return FALSE;
    }

    switch (nhdr->hdr.code) {

    case LVN_COLUMNCLICK:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            pDlgContext->bInverseSort = !pDlgContext->bInverseSort;
            pDlgContext->lvColumnToSort = ((NMLISTVIEW*)nhdr)->iSubItem;

            ListView_SortItemsEx(
                pDlgContext->ListView,
                &DesktopListCompareFunc,
                pDlgContext);

            if (pDlgContext->bInverseSort)
                nImageIndex = 1;
            else
                nImageIndex = 2;

            supUpdateLvColumnHeaderImage(
                pDlgContext->ListView,
                pDlgContext->lvColumnCount,
                pDlgContext->lvColumnToSort,
                nImageIndex);
        }
        break;

    case NM_DBLCLK:
        DesktopListShowProperties(hwndDlg);
        break;

    default:
        return FALSE;
    }

    return TRUE;
}

/*
* DesktopListDialogProc
*
* Purpose:
*
* Desktop list page.
*
* WM_INITDIALOG - Initialize listview.
* WM_NOTIFY - Handle list view notifications.
* WM_SHOWWINDOW - Collect desktop info and fill list.
* WM_DESTROY - Free image list.
*
*/
INT_PTR CALLBACK DesktopListDialogProc(
    _In_ HWND hwndDlg,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam
)
{
    PROPSHEETPAGE* pSheet;
    PROP_OBJECT_INFO* Context = NULL;
    EXTRASCONTEXT* pDlgContext = NULL;

    switch (uMsg) {

    case WM_SHOWWINDOW:
        if (wParam) {
            Context = (PROP_OBJECT_INFO*)GetProp(hwndDlg, T_PROPCONTEXT);
            pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
            if ((Context) && (pDlgContext)) {

                DesktopListSetInfo(hwndDlg, Context, pDlgContext);
                if (pDlgContext->ListView) {

                    ListView_SortItemsEx(
                        pDlgContext->ListView,
                        &DesktopListCompareFunc,
                        pDlgContext);
                }
                return 1;
            }
        }
        break;

    case WM_NOTIFY:
        return DesktopListHandleNotify(hwndDlg, lParam);

    case WM_DESTROY:
        pDlgContext = (EXTRASCONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (pDlgContext) {
            if (pDlgContext->ImageList) {
                ImageList_Destroy(pDlgContext->ImageList);
            }
            supHeapFree(pDlgContext);
        }
        RemoveProp(hwndDlg, T_DLGCONTEXT);
        RemoveProp(hwndDlg, T_PROPCONTEXT);
        break;

    case WM_INITDIALOG:
        pSheet = (PROPSHEETPAGE*)lParam;
        if (pSheet) {
            SetProp(hwndDlg, T_PROPCONTEXT, (HANDLE)pSheet->lParam);
            pDlgContext = (EXTRASCONTEXT*)supHeapAlloc(sizeof(EXTRASCONTEXT));
            if (pDlgContext) {
                SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)pDlgContext);
                DesktopListCreate(hwndDlg, pDlgContext);
            }
        }
        return 1;

    }
    return 0;
}
