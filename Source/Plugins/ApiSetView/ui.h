/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2019 - 2020
*
*  TITLE:       UI.H
*
*  VERSION:     1.01
*
*  DATE:        30 Nov 2020
*
*  WinObjEx64 ApiSetView UI constants, definitions and includes.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")

#define DefaultSystemDpi            96
#define WINOBJEX64_ICON_MAIN        174

typedef struct _GUI_CONTEXT {
    HWND MainWindow;
    HWND TreeList;
    HANDLE PluginHeap;
    HANDLE WorkerThread;
    HICON WindowIcon;

    //
    // WinObjEx64 data and pointers.
    //
    WINOBJEX_PARAM_BLOCK ParamBlock;
} GUI_CONTEXT, *PGUI_CONTEXT;

typedef struct _TL_SUBITEMS_FIXED {
    ULONG       ColorFlags;
    COLORREF    BgColor;
    COLORREF    FontColor;
    PVOID       UserParam;
    ULONG       Count;
    LPTSTR      Text[2];
} TL_SUBITEMS_FIXED, * PTL_SUBITEMS_FIXED;
