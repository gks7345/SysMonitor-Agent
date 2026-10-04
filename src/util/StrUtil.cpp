#include "util/StrUtil.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

namespace StrUtil {
    std::string wideToUtf8(std::wstring_view w) {
        if (w.empty()) return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
        if (len <= 0) return {};
        std::string out(static_cast<size_t>(len), '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), out.data(), len, nullptr, nullptr);
        return out;
    }

    std::wstring utf8ToWide(std::string_view s) {
        if (s.empty()) return {};
        int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
        if (len <= 0) return {};
        std::wstring out(static_cast<size_t>(len), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), len);
        return out;
    }

    // Windows 11 메모장은 "Notepad.exe"라 정확 일치로는 "notepad" 등록이 영원히 매칭되지 않았다.
    std::wstring_view exeBaseName(std::wstring_view exe) {
        constexpr std::wstring_view ext = L".exe";
        if (exe.size() > ext.size() &&
            CompareStringOrdinal(
                exe.data() + exe.size() - ext.size(), static_cast<int>(ext.size()),
                ext.data(), static_cast<int>(ext.size()),
                TRUE) == CSTR_EQUAL) {
            exe.remove_suffix(ext.size());
        }
        return exe;
    }

    bool sameExeName(std::wstring_view a, std::wstring_view b) {
        return CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b.data(), static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
    }

    bool sameExeName(const std::string& a, const std::string& b) {
        return sameExeName(utf8ToWide(a), utf8ToWide(b));
    }
}
