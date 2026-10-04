#include "util/ProcessList.h"
#include "util/StrUtil.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <tlhelp32.h>

std::optional<ProcessList> takeProcessList() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return std::nullopt;

    // W 버전 — ANSI 버전은 코드 페이지에 없는 문자를 '?'로 바꾸고 한글을 CP949로 준다
    ProcessList procs;
    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            procs.push_back(ProcessListEntry{ entry.th32ProcessID, entry.th32ParentProcessID,
                std::wstring(StrUtil::exeBaseName(entry.szExeFile)) });
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return procs;
}
