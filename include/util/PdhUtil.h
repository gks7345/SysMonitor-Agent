#pragma once
#include <Windows.h>
#include <Pdh.h>
#include <PdhMsg.h>
#include <cmath>
#include <spdlog/spdlog.h>

namespace PdhUtil {
    inline double getDouble(PDH_HCOUNTER counter) {
        PDH_FMT_COUNTERVALUE val = {};

        PDH_STATUS status = PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, NULL, &val);
        if (status != ERROR_SUCCESS) {
            spdlog::error("val Status ERROR 0x{:X}", status);
            return 0.0;
        }

        if (val.CStatus != PDH_CSTATUS_VALID_DATA && val.CStatus != PDH_CSTATUS_NEW_DATA) {
            spdlog::error("CStatus ERROR 0x{:X}", val.CStatus);
            return 0.0;
        }

        // CStatus가 유효해도 doubleValue 자체가 NaN/Inf인 경우가 있어 (일부 카운터의 내부 계산이
        // 0으로 나누는 경우 등) hot tier/API로 그대로 흘러가면 nlohmann::json 직렬화가 깨질 수 있음
        if (std::isnan(val.doubleValue) || std::isinf(val.doubleValue)) return 0.0;

        return val.doubleValue;
    }
}
