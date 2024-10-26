#pragma once
/*
Copyright (c) BOL
Licensed under the MIT license.

Description:
- Memory namespace providing the required functions to handle memory actions.

Author(s):
- Jiingz
*/

#include <cstdint>
#include <wtypes.h>

#include "util/console.h"
#ifndef MEMORY_H
#define MEMORY_H
#include "Bypass.h"

#define TARGET_PROCESS L"VALORANT-Win64-Shipping.exe"

#define IS_VALID_ADDRESS(address) ((address) != 0 && (address) > 0x1000)

//from http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/bigpool_entry.htm
typedef struct _SYSTEM_BIGPOOL_ENTRY
{
    union
    {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };

    ULONG_PTR SizeInBytes;

    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

//from http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/bigpool.htm
typedef struct _SYSTEM_BIGPOOL_INFORMATION
{
    ULONG Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

typedef enum _SYSTEM_INFO_CLASS
{
    SystemBigPoolInformation = 0x42 // might require an update depending on OS, need to test.
} SYSTEM_INFO_CLASS;

typedef NTSTATUS (WINAPI*pNtQuerySystemInformation)(
    IN SYSTEM_INFO_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength
);


namespace memory
{
    enum ActionType
    {
        ActionUnknown,
        ActionOpenProcess,
        ActionReadMemory,
        ActionWriteMemory,
        ActionModuleQuery
    };

    enum ActionStatus
    {
        StatusInvalid,
        StatusPending,
        StatusError,
        StatusDone
    };

    typedef struct _ControlData
    {
        ActionType Action;
        ActionStatus Status;
        uint64_t Data[5];
    } ControlData;

    void HandleOpenProcess(volatile ControlData* data);
    void HandleReadMemory(volatile ControlData* data);
    void HandleWriteMemory(volatile ControlData* data);
    void HandleModuleQuery(volatile ControlData* data);
    ActionStatus PerformAction(ActionType type, uint64_t data1 = 0, uint64_t data2 = 0, uint64_t data3 = 0,
                               uint64_t data4 = 0, uint64_t data5 = 0);
    void Loop();
}

namespace memory_manager
{
    DWORD GetProcessPID(const wchar_t* processName);
    uint64_t GetModuleAddress(const wchar_t* moduleName);
    void WaitAndOpenProcess(const wchar_t* processName);
    bool ReadMemory(uint64_t address, void* buffer, size_t size);
    bool WriteMemory(uint64_t address, void* buffer, size_t size);
    static uint64_t BaseAddress;
    static uintptr_t guard;

    template <typename T>
    static T ReadUnguarded(uint64_t address)
    {
        if (!IS_VALID_ADDRESS(address))
            return T{};
        T buffer{};

        try
        {
            ReadMemory(address, &buffer, sizeof(T));
        }
        catch (const std::exception& e)
        {
            LOG("Exception occurred while reading [UNGUARDED] memory at address: %p", address);
            return buffer;
        }

        return buffer;
    }

    inline bool IsHandleValid(HANDLE handle) {
        DWORD flags;
        if (GetHandleInformation(handle, &flags)) {
            return true;
        } else {
            return false;
        }
    }

    static __forceinline auto QueryBigPools() -> PSYSTEM_BIGPOOL_INFORMATION
    {
        static const pNtQuerySystemInformation NtQuerySystemInformation =
            (pNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

        DWORD length = 0;
        DWORD size = 0;
        LPVOID heap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0);
        heap = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, heap, 0xFF);
        NTSTATUS ntLastStatus = NtQuerySystemInformation(SystemBigPoolInformation, heap, 0x30, &length);
        heap = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, heap, length + 0x1F);
        size = length;
        ntLastStatus = NtQuerySystemInformation(SystemBigPoolInformation, heap, size, &length);

        return reinterpret_cast<PSYSTEM_BIGPOOL_INFORMATION>(heap);
    }

    static bool IsGuardedRegion(uintptr_t pointer)
    {
        static constexpr uintptr_t filter = 0xFFFFFFF000000000;
        uintptr_t result = pointer & filter;
        return result == 0x8000000000 || result == 0x10000000000;
    }

    static uint64_t ValidateGuardPointer(uint64_t address)
    {
        if (IsGuardedRegion(address))
            return guard + (address & 0xFFFFFF);
        else
            return address;
    }

    static __forceinline auto GetGuardedRegion() -> uintptr_t
    {
        if (guard != 0)
            return guard;

        auto pool_information = QueryBigPools();

        if (pool_information)
        {
            auto count = pool_information->Count;
            for (auto i = 0ul; i < count; i++)
            {
                SYSTEM_BIGPOOL_ENTRY* allocation_entry = &pool_information->AllocatedInfo[i];
                const auto virtual_address = (PVOID)((uintptr_t)allocation_entry->VirtualAddress & ~1ull);
                if (allocation_entry->NonPaged && allocation_entry->SizeInBytes == 0x200000)
                    if (guard == 0 && allocation_entry->TagUlong == 'TnoC')
                    {
                        if (memory_manager::ReadUnguarded<uintptr_t>(
                            reinterpret_cast<uintptr_t>(virtual_address) + 0x60) != 0)
                        {
                            guard = reinterpret_cast<uintptr_t>(virtual_address);
                            LOGDEBUG("Guarded Region: %p", guard);
                        }
                    }
            }
        }

        return guard;
    }


    template <typename T>
    static T ReadGuarded(uintptr_t address)
    {
        T buffer;
        ReadMemory(address, &buffer, sizeof(T));
        uintptr_t val = GetGuardedRegion() + (*(uintptr_t*)&buffer & 0xFFFFFF);
        return *(T*)&val;
    }

    template <typename T>
    static T Read(uint64_t address)
    {
        // if (!IS_VALID_ADDRESS(address))
        //     return T{};

        T buffer{};

        ReadMemory(address, &buffer, sizeof(T));

        if (IsGuardedRegion((uintptr_t)buffer))
        {
            return ReadGuarded<uintptr_t>(address);
        }

        return buffer;
    }

    template <typename T>
    static bool Write(DWORD64 address, T value)
    {
        return false;
        return WriteMemory(address, &value, sizeof(value));
    }
}

#endif
