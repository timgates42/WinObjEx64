/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020 - 2021
*
*  TITLE:       SDVIEWDLG.C
*
*  VERSION:     1.88
*
*  DATE:        30 Nov 2020
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "sdviewDlg.h"


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

/*
* SDViewDialogResize
*
* Purpose:
*
* WM_SIZE handler.
*
*/
VOID SDViewDialogResize(
    _In_ HWND hwndDlg
)
{
    RECT r, szr;
    HWND hwnd, hwndStatusBar;

    RtlSecureZeroMemory(&r, sizeof(RECT));
    RtlSecureZeroMemory(&szr, sizeof(RECT));

    hwnd = GetDlgItem(hwndDlg, ID_SDVIEWLIST);
    hwndStatusBar = GetDlgItem(hwndDlg, ID_SDVIEW_STATUSBAR);
    GetClientRect(hwndDlg, &r);
    GetClientRect(hwndStatusBar, &szr);

    SendMessage(hwndStatusBar, WM_SIZE, 0, 0);

    SetWindowPos(hwnd, 0, 0, 0,
        r.right,
        r.bottom - szr.bottom,
        SWP_NOZORDER);
}

/*
* SDViewDialogProc
*
* Purpose:
*
* View Security Descriptor Dialog Window Procedure
*
* During WM_INITDIALOG centers window and initializes system info
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
            SetProp(hwndDlg, T_DLGCONTEXT, (HANDLE)lParam);
        }
        SDViewDialogResize(hwndDlg);
        break;

    case WM_GETMINMAXINFO:
        if (lParam) {
            ((PMINMAXINFO)lParam)->ptMinTrackSize.x = 640;
            ((PMINMAXINFO)lParam)->ptMinTrackSize.y = 480;
        }
        break;

    case WM_SIZE:
        SDViewDialogResize(hwndDlg);
        break;

    case WM_CLOSE:
        sdvContext = (SDVIEW_CONTEXT*)GetProp(hwndDlg, T_DLGCONTEXT);
        if (sdvContext) {
            if (sdvContext->DialogIcon)
                DestroyIcon(sdvContext->DialogIcon);

            FreeSDViewContext(sdvContext);
            RemoveProp(hwndDlg, T_DLGCONTEXT);
        }
        return DestroyWindow(hwndDlg);

    case WM_COMMAND:

        switch (GET_WM_COMMAND_ID(wParam, lParam)) {
        case IDCANCEL:
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
    SDVIEW_CONTEXT* SDViewContext;

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
    }
}
