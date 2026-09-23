#pragma once
#include <string>
#include <chrono>
#include <ctime>

namespace DateUtil {
    inline std::string today() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::tm tm = {};
        localtime_s(&tm, &time);
        char buf[16];
        strftime(buf, sizeof(buf), "%Y-%m-%d", &tm);
        return std::string(buf);
    }
}
