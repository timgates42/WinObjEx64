/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2020
*
*  TITLE:       SDVIEWDLG.H
*
*  VERSION:     1.88
*
*  DATE:        30 Nov 2020
*
*  Common header file for the SecurityDescriptor View Dialog.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

typedef struct _SDVIEW_CONTEXT {
    HWND DialogWindow;
    HICON DialogIcon;
    LPWSTR Directory;
    LPWSTR Name;
    WOBJ_OBJECT_TYPE Type;
} SDVIEW_CONTEXT, * PSDVIEW_CONTEXT;

VOID SDViewDialogCreate(
    _In_ HWND ParentWindow,
    _In_ LPWSTR ObjectDirectory,
    _In_opt_ LPWSTR ObjectName,
    _In_ WOBJ_OBJECT_TYPE ObjectType);
