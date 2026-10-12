#pragma once
#include <optional>
#include <string>
#include <vector>

// 실행 중인 프로세스 한 건 (ToolHelp32 스냅샷).
// 이 헤더는 <Windows.h>를 끌어오지 않도록 PID를 기본 타입(DWORD와 같은 unsigned long)으로 둔다.
struct ProcessListEntry {
    unsigned long pid = 0;
    unsigned long ppid = 0;     // 부모 PID — 부모가 종료돼도 Windows는 이 값을 고치지 않는다
    std::wstring exeName;       // 실행 파일 이름(.exe 제외, OS가 준 대소문자 그대로)
};
using ProcessList = std::vector<ProcessListEntry>;

// 실행 중인 프로세스 목록을 뜬다. 메인 루프가 틱당 1번 불러 ProcessCollector와 TargetCollector에 함께 넘긴다 —
// 두 수집기가 같은 시점의 목록을 보고, 스냅샷을 각자 뜨지 않는다.
// 권한이 필요 없고, 종료된 프로세스는 다른 프로세스가 핸들을 쥐고 있어도 목록에서 빠진다
// (OpenProcess는 두 경우 모두 틀린 답을 준다).
// nullopt = 스냅샷 자체가 실패. 빈 목록("아무것도 실행 중이 아님")과 다르다 — 받는 쪽은 이번 틱의 판정을 건너뛴다.
std::optional<ProcessList> takeProcessList();
