#include <iostream>
#include "ReflectiveInjector.h"

int main()
{
    ReflectiveInjector injector;
    injector.RemoteThreadInject(41548, L"..\\x64\\Release\\ReflectiveModule.dll");
}

