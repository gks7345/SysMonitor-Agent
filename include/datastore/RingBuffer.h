#pragma once
#include <vector>
#include <stdexcept>

template <typename Q>
class RingBuffer {
private:
    size_t sz;
    size_t cap;
    size_t frontIdx;
    size_t backIdx;
    size_t unflushedCount; // 마지막 flush 이후 새로 쌓인 개수 (cap으로 saturate)
    std::vector<Q> data;

public:
    RingBuffer(size_t capacity)
        : sz(0), cap(capacity)
        , frontIdx(0), backIdx(0)
        , unflushedCount(0)
        , data(capacity) {
    }

    void enQueue(const Q* q, size_t block) {
        for (size_t i = 0; i < block; i++) {
            enQueue(q[i]);
        }
    }

    void enQueue(const Q& q) {
        data[backIdx] = q;
        backIdx = (backIdx + 1) % cap;
        // cap개 이상 쌓여도 어차피 오래된 데이터부터 덮어써지므로 cap으로 saturate
        unflushedCount = (std::min)(unflushedCount + 1, cap);

        if (sz >= cap) {
            //가득 찼으면 front도 같이 이동
            frontIdx = (frontIdx + 1) % cap;
            return;
        }
        sz++;
    }

    // -------------------------------------------------------
    // flush용 — 마지막 flush 이후 새 데이터만 반환 (데이터 삭제 없음)
    // 위치(커서) 대신 개수(unflushedCount)로 추적 — backIdx에서 역산하므로
    // "0개 쌓임"과 "cap개 쌓임"이 같은 인덱스로 나오는 모호성이 없음
    // -------------------------------------------------------
    std::vector<Q> peekNew() {
        std::vector<Q> result;
        if (unflushedCount == 0) return result;

        result.reserve(unflushedCount);
        size_t idx = (backIdx + cap - unflushedCount) % cap;
        for (size_t i = 0; i < unflushedCount; ++i) {
            result.push_back(data[idx]);
            idx = (idx + 1) % cap;
        }
        unflushedCount = 0;
        return result;
    }
    // flush 후 비우고 싶을 때
    std::vector<Q> deQueue() {
        std::vector<Q> result;
        result.reserve(sz);

        size_t idx = frontIdx;
        for (size_t i = 0; i < sz; i++) {
            result.push_back(data[idx]);
            idx = (idx + 1) % cap;
        }

        sz = 0;
        frontIdx = 0;
        backIdx = 0;
        unflushedCount = 0;
        return result;
    }

    // -------------------------------------------------------
    // latest — 최근 N개 읽기 (비파괴적, API용)
    // -------------------------------------------------------
    std::vector<Q> latest(size_t n) const {
        n = (std::min)(n, sz);
        std::vector<Q> result;
        result.reserve(n);

        size_t idx = (backIdx + cap - n) % cap;
        for (size_t i = 0; i < n; i++) {
            result.push_back(data[idx]);
            idx = (idx + 1) % cap;
        }
        return result;
    }

    std::vector<Q> popQueue(size_t n) {
        n = (std::min)(n, sz);
        std::vector<Q> result;
        result.reserve(n);

        for (size_t i = 0; i < n; i++) {
            result.push_back(data[frontIdx]);
            frontIdx = (frontIdx + 1) % cap;
        }
        sz -= n;
        return result;
    }

    size_t getSize()     const { return sz; }
    size_t getCapacity() const { return cap; }
    bool   isEmpty()     const { return sz == 0; }
    bool   isFull()      const { return sz == cap; }
};