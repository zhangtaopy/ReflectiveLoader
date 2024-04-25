#pragma once
#include <windows.h>
#include "wow64ext/wow64ext.h"
#include "ReflectiveDef.h"
#include "ProcessOpWrapper.h"
/*
	x86 -> x86
	x64 -> x64
	x86 -> x64
*/

class ReflectiveInjector
{
public:
	ReflectiveInjector();
	~ReflectiveInjector();

public:
	BOOL ApcInject(DWORD dwPid, DWORD dwTid, LPCWSTR lpModuleName);
	BOOL RemoteThreadInject(DWORD dwPid, LPCWSTR lpModuleName);

protected:
	BOOL _MapFileAndParamToRemote(
		ProcessOpWrapper& ProcessHelper,
		LPCWSTR lpModuleName,  
		ADDR_T& ReflectiveLoaderAddr,
		ADDR_T& ParamAddr);
};