#pragma once
#include <string>
#include <string_view>

// 수집기 문자열은 전부 UTF-8 std::string으로 통일한다 (기획노트 Phase 3-0).
// Win32 API는 W 버전으로 호출하고, 결과를 여기서 UTF-8로 바꾼다 — A 버전은 PC 코드 페이지(한글 Windows는 CP949)에
// 의존해서, 한글 프로세스명·경로가 proto string의 UTF-8 검증에 걸려 스트림이 끊기거나 DuckDB에 깨진 채 저장된다.
// 반대로 UTF-8 이름을 Win32 API(예: PDH 카운터 경로)에 넘길 때는 utf8ToWide()로 바꿔 W 버전에 넘긴다.
// 구현은 src/util/StrUtil.cpp — 이 헤더는 <Windows.h>를 끌어오지 않아 include 순서와 무관하게 쓸 수 있다
// (winsock.h/winsock2.h 충돌, min/max 매크로 오염 방지).
namespace StrUtil {
    std::string wideToUtf8(std::wstring_view w);
    std::wstring utf8ToWide(std::string_view s);

    // 실행 파일 이름 규칙 — Windows 파일 이름과 같다.
    // 타겟(TargetCollector)과 proc 목록(ProcessCollector)이 이 규칙 하나를 쓴다 — 서버로 나가는 프로세스 이름에는 ".exe"가 없다.
    // 끝의 ".exe"를 대소문자 무관하게 뗀 부분을 돌려준다 (인자를 가리키는 view — 인자가 살아 있는 동안만 유효).
    std::wstring_view exeBaseName(std::wstring_view exe);
    // 대소문자를 무시하는 서수 비교 (파일 시스템과 같은 방식, CompareStringOrdinal)
    bool sameExeName(std::wstring_view a, std::wstring_view b);
    bool sameExeName(const std::string& a, const std::string& b);   // UTF-8
}
