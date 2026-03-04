#pragma once

#include <windows.h>
#include <cstring>

template <typename T>
T Asm_ReadMemory(DWORD_PTR address)
{
    T value = NULL;
    if (!IsBadReadPtr(reinterpret_cast<const void*>(address), sizeof(T)))
    {
        memcpy(&value, reinterpret_cast<const void*>(address), sizeof(T));
    }
    return value;
}

template <typename T>
void Asm_WriteMemory(DWORD_PTR address, T value)
{
    if (!IsBadWritePtr(reinterpret_cast<void*>(address), sizeof(T)))
    {
        memcpy(reinterpret_cast<void*>(address), &value, sizeof(T));
    }
}
