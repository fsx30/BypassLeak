// Copyright (c) BOL
// Licensed under the MIT license.

#include "../general.h"
#include "../util/console.h"
#include "../util/Obf.hpp"

DWORD targetPid = 0;
HANDLE targetProcess;


volatile memory::ControlData controlData;
std::mutex actionMutex;

void memory::HandleOpenProcess(volatile ControlData* data)
{
    DWORD processId = static_cast<DWORD>(data->Data[0]);

    targetProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, processId);

    if (!targetProcess || targetProcess == INVALID_HANDLE_VALUE)
    {
        LOG("HANDLE!!!!!!!!!!!!!!!!");
        data->Status = StatusError;
        return;
    }

    data->Status = StatusDone;
}

void memory::HandleReadMemory(volatile ControlData* data)
{
    if (!IS_VALID_ADDRESS(data->Data[0]))
    {
        data->Status = StatusError;
        return;
    }
    if (targetProcess == NULL)
    {
        LOG("Invalid process handle");
        data->Status = StatusError;
        return;
    }

    if (data == NULL)
    {
        LOG("Invalid data ptr");
        data->Status = StatusError;
        return;
    }

    if (data->Data[0] == 0 || data->Data[1] == 0)
    {
        LOG("Invalid memory address or buffer pointer: Address: %p, Buffer: %p", (void*)data->Data[0],
            (void*)data->Data[1]);
        data->Status = StatusError;
        return;
    }

    if (data->Data[2] == 0)
    {
        LOG("Invalid size: %llu", data->Data[2]);
        data->Status = StatusError;
        return;
    }

    bool status = ReadProcessMemory(targetProcess, reinterpret_cast<LPCVOID>(data->Data[0]),
                                    reinterpret_cast<LPVOID>(data->Data[1]), data->Data[2],
                                    const_cast<SIZE_T*>(&data->Data[3]));
    if (!status)
    {
        LOG("Failed to read memory: Address: %p, Buffer: %p, Size: %llu", (void*)data->Data[0], (void*)data->Data[1],
            data->Data[2]);
        data->Status = StatusError;
        //Sleep(5000);
        return;
    }

    data->Status = StatusDone;
}

typedef NTSTATUS(WINAPI* _NtWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytesToWrite,
    _Out_opt_ PULONG NumberOfBytesWritten
    );

void memory::HandleWriteMemory(volatile ControlData* data)
{
    if (targetProcess == NULL)
    {
        LOG("Invalid process handle");
        data->Status = StatusError;
        return;
    }

    if (data == NULL)
    {
        LOG("Invalid data ptr");
        data->Status = StatusError;
        return;
    }

    if (data->Data[0] == 0 || data->Data[1] == 0)
    {
        LOG("Invalid memory address or buffer pointer: Address: %p, Buffer: %p", (void*)data->Data[0],
            (void*)data->Data[1]);
        data->Status = StatusError;
        return;
    }

    if (data->Data[2] == 0)
    {
        LOG("Invalid size: %llu", data->Data[2]);
        data->Status = StatusError;
        return;
    }

    LPVOID address = reinterpret_cast<LPVOID>(data->Data[0]);
    LPVOID buffer = reinterpret_cast<LPVOID>(data->Data[1]);
    SIZE_T size = data->Data[2];
    SIZE_T* outputSize = const_cast<SIZE_T*>(&data->Data[3]);
    //bool status = WriteProcessMemory(targetProcess, address, buffer, size, outputSize);

    HANDLE targetHandle;

    if(memory_manager::IsGuardedRegion(data->Data[0]))
    {
        targetHandle = GetCurrentProcess();
    }
    else
    {
        targetHandle = targetProcess;
    }
    
    _NtWriteVirtualMemory pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    bool status = pNtWriteVirtualMemory(targetHandle, (LPVOID)address, buffer, size, NULL);
      
    if (!status)
    {
       // std::cout << "Failed to access memory. The Aimbot won't work." << std::endl;
       // std::cout << "If you want to use the aimbot please restart your computer and run again." << std::endl;
        LOG("Failed to write memory: Address: %p, Buffer: %p, Size: %llu | ERROR: %i", (void*)data->Data[0], (void*)data->Data[1],
            data->Data[2], GetLastError());
        data->Status = StatusError;
        return;
    }
    else
    {
        LOG("Success to write memory: Address: %p, Buffer: %p, Size: %llu", (void*)data->Data[0], (void*)data->Data[1],
            data->Data[2]);
    }

    data->Status = StatusDone;
}

void memory::HandleModuleQuery(volatile ControlData* data)
{
    wchar_t* moduleName = reinterpret_cast<wchar_t*>(data->Data[0]);
    uint64_t modBaseAddr = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPid);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32FirstW(snapshot, &modEntry))
        {
            do
            {
                if (!_wcsicmp(modEntry.szModule, moduleName))
                {
                    modBaseAddr = reinterpret_cast<uint64_t>(modEntry.modBaseAddr);
                    break;
                }
            }
            while (Module32NextW(snapshot, &modEntry));
        }
    }
    CloseHandle(snapshot);

    *reinterpret_cast<uint64_t*>(data->Data[1]) = modBaseAddr;
    if (!modBaseAddr)
    {
        data->Status = StatusError;
        return;
    }

    data->Status = StatusDone;
}

memory::ActionStatus memory::PerformAction(ActionType type, uint64_t data1, uint64_t data2, uint64_t data3,
                                           uint64_t data4, uint64_t data5)
{
    actionMutex.lock();
    memset((void*)&controlData, 0, sizeof(ControlData));

    controlData.Action = type;
    controlData.Data[0] = data1;
    controlData.Data[1] = data2;
    controlData.Data[2] = data3;
    controlData.Data[3] = data4;
    controlData.Data[4] = data5;

    controlData.Status = StatusPending;

    //	if(type != ActionReadMemory && type != ActionWriteMemory)
    while (controlData.Status == StatusPending)
    {
    }

    actionMutex.unlock();
    return controlData.Status;
}

void memory::Loop()
{
    while (!global::ShouldExit)
    {
        if (GetAsyncKeyState(VK_F10) & 0x8000)
        {
            Sleep(1000);
            break;
        }

        if (controlData.Status != StatusPending)
            continue;

        switch (controlData.Action)
        {
        case ActionOpenProcess:
            HandleOpenProcess(&controlData);
            break;
        case ActionReadMemory:
            HandleReadMemory(&controlData);
            break;
        case ActionWriteMemory:
            HandleWriteMemory(&controlData);
            break;
        case ActionModuleQuery:
            HandleModuleQuery(&controlData);
            break;
        default:
            break;
        }
    }
    HANDLE hProcess = GetCurrentProcess();
    TerminateProcess(hProcess, 0);
}

DWORD memory_manager::GetProcessPID(const wchar_t* processName)
{
    PROCESSENTRY32W processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    Process32FirstW(snapshot, &processInfo);

    if (!wcscmp(processName, processInfo.szExeFile))
    {
        CloseHandle(snapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32NextW(snapshot, &processInfo))
    {
        if (!wcscmp(processName, processInfo.szExeFile))
        {
            CloseHandle(snapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(snapshot);
    return 0;
}

uint64_t memory_manager::GetModuleAddress(const wchar_t* moduleName)
{
    if (!BaseAddress)
    {
        memory::ActionStatus status = memory::PerformAction(memory::ActionModuleQuery,
                                                            reinterpret_cast<uint64_t>(moduleName),
                                                            reinterpret_cast<uint64_t>(&BaseAddress));
    }

    return BaseAddress;
}

// Function to convert uint64_t to const wchar_t*
const wchar_t* uint64ToString(uint64_t value)
{
    // Convert the integer to a wide character string
    std::wstringstream ss;
    ss << value;
    std::wstring str = ss.str();

    // Create a wide character array to hold the string
    wchar_t* result = new wchar_t[str.length() + 1];
    wcscpy(result, str.c_str());

    return result;
}

void memory_manager::WaitAndOpenProcess(const wchar_t* processName)
{
    LOG("Waiting for the game to open...");

    targetPid = GetProcessPID(processName);

    while (!targetPid)
    {
        targetPid = GetProcessPID(processName);
    }
    
    LOG("Game found!");

    memory::ActionStatus status = memory::PerformAction(memory::ActionOpenProcess, targetPid);
    if (status != memory::StatusDone)
    {
        LOG("Failed to connect to the game!");
        Sleep(INT_MAX);
    }
}

bool memory_manager::ReadMemory(uint64_t address, void* buffer, size_t size)
{
    memory::ActionStatus status = memory::PerformAction(memory::ActionReadMemory, address,
                                                        reinterpret_cast<uint64_t>(buffer), size);
    return status == memory::StatusDone;
}

bool memory_manager::WriteMemory(uint64_t address, void* buffer, size_t size)
{
    memory::ActionStatus status = memory::PerformAction(memory::ActionWriteMemory, address,
                                                        reinterpret_cast<uint64_t>(buffer), size);
    return status == memory::StatusDone;
}
