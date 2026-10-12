#pragma once
#include <Windows.h>
#include <Pdh.h>
#include <PdhMsg.h>
#include <cmath>
#include <optional>
#include <string_view>
#include <spdlog/spdlog.h>
#include "util/StrUtil.h"

namespace PdhUtil {
    // 카운터를 쿼리에 등록한다. 영문 이름으로 등록해 다른 언어의 Windows에서도 같은 경로가 통하게 한다.
    // 실패하면 counter는 nullptr이고 그 지표는 계속 "없음"으로 나간다. 실패한 이유(카운터 없음, 객체 없음 등)는
    // 여기에만 남는다 — 그 뒤의 읽기 실패는 언제나 "잘못된 핸들"로만 보인다.
    inline void addCounter(PDH_HQUERY query, const wchar_t* path, PDH_HCOUNTER& counter, std::string_view owner) {
        const PDH_STATUS status = PdhAddEnglishCounterW(query, path, 0, &counter);
        if (status == ERROR_SUCCESS) return;

        counter = nullptr;
        spdlog::error("{}: counter '{}' could not be added (0x{:X}) — that metric will be unavailable",
            owner, StrUtil::wideToUtf8(path), static_cast<unsigned>(status));
    }

    // 카운터 하나를 읽은 결과. value가 없으면 읽지 못한 것이고, status가 그 이유다
    // (PDH 함수의 반환값, 또는 값은 왔지만 쓸 수 없을 때 그 항목의 CStatus / PDH_INVALID_DATA).
    struct Reading {
        std::optional<double> value;
        PDH_STATUS status = ERROR_SUCCESS;
    };

    // 읽지 못한 값을 0으로 돌려주지 않는다 — 0은 실제 측정값과 구분되지 않는다.
    // 매 틱 불리므로 여기서 로그를 찍지 않는다 (알릴지는 호출부가 reportReadState()로 정한다).
    inline Reading read(PDH_HCOUNTER counter) {
        PDH_FMT_COUNTERVALUE val = {};

        const PDH_STATUS status = PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, NULL, &val);
        if (status != ERROR_SUCCESS) return { std::nullopt, status };

        if (val.CStatus != PDH_CSTATUS_VALID_DATA && val.CStatus != PDH_CSTATUS_NEW_DATA)
            return { std::nullopt, static_cast<PDH_STATUS>(val.CStatus) };

        // CStatus가 유효해도 doubleValue 자체가 NaN/Inf인 경우가 있다 (일부 카운터의 내부 계산이 0으로 나누는 경우 등)
        if (std::isnan(val.doubleValue) || std::isinf(val.doubleValue))
            return { std::nullopt, static_cast<PDH_STATUS>(PDH_INVALID_DATA) };

        return { val.doubleValue, ERROR_SUCCESS };
    }

    // 값의 단위만 바꾼다 (값이 없으면 그대로 없음)
    inline Reading scaled(Reading r, double factor) {
        if (r.value) *r.value *= factor;
        return r;
    }

    // 읽기 실패를 알린다. 같은 실패가 매 틱 쌓이지 않게 실패가 시작될 때 1번만 알리고, 다시 읽히면 그 사실도 1번 알린다.
    // 값은 "없음"으로 나가므로 받는 쪽에서는 원인을 알 수 없다 — 무엇이 왜 읽히지 않는지는 여기에만 남는다.
    // warned: 그 값 하나에 대한 상태 (호출부가 값마다 하나씩 들고 있는다)
    inline void reportReadState(bool& warned, bool ok, std::string_view owner, std::string_view what, PDH_STATUS status) {
        if (!ok && !warned) {
            warned = true;
            spdlog::warn("{}: '{}' could not be read (0x{:X}) — it is sent as N/A, not 0, until it reads again", owner, what, static_cast<unsigned>(status));
        }
        else if (ok && warned) {
            warned = false;
            spdlog::info("{}: '{}' reads again", owner, what);
        }
    }
}
