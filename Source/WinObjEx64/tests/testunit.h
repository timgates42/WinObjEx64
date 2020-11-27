/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2020
*
*  TITLE:       TESTUNIT.H
*
*  VERSION:     1.88
*
*  DATE:        26 Nov 2020
*
*  Common header file for test code.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#pragma once

VOID TestStart(VOID);
VOID TestStop(VOID);
VOID TestException(_In_ BOOL bNaked);
HANDLE TestGetPortHandle();
