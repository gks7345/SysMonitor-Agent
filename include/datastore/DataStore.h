// DataStore.h
#pragma once
#include <string>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <shared_mutex>
#include "datastore/RingBuffer.h"
#include "duckdb.hpp"
#include "models/SnapshotData.h"

class DataStore {
private:
    RingBuffer<SnapshotProcData> procsData;
    RingBuffer<SnapshotSysData>  sysData;
    RingBuffer<SnapshotTargetData>  targetData;

    static std::string makeDailyDbPath();

    std::string currentDbPath;
    duckdb::DuckDB     db;
    duckdb::Connection con;

    mutable std::shared_mutex procMtx;
    mutable std::shared_mutex sysMtx;
    mutable std::shared_mutex targetMtx;
    mutable std::mutex dbMtx;

    // 날짜 범위 내 DB 파일 목록가져오기
    std::string getDbFilePath(const std::string& date);
    // 다른 날짜의 DB 파일을 DuckDB ATTACH로 임시로 붙여서 조회
    // 프로그램 실행 중 꺼졌다가 다시 켠 시간태(gap) 계산 -> 해당 날짜의 비어있는 시간대
    // selectSql의 물음표(?)는 params에 위치 순서대로 바인드됨 (Prepare/Execute — SQL injection 방지)
    std::string attachAndQuery(const std::string& date, const std::string& selectSql, duckdb::vector<duckdb::Value> params, std::function<nlohmann::json(duckdb::DataChunk*, size_t)> rowMapper);

    void initDB();

    // date가 "YYYY-MM-DD" 형식(자릿수/구분자/숫자 여부)인지 검증.
    // attachAndQuery/queryTargetRangeJson이 date를 SQL 문자열에 직접 삽입(ATTACH 별칭, {db} 치환)하기 전에
    // 방어적으로 한 번 더 확인한다 — ApiServer::validateDate()가 이미 검증하지만,
    // 데이터 계층 자체의 신뢰 경계를 명확히 하기 위해 호출자에게만 의존하지 않는다.
    static bool isValidDateFormat(const std::string& date);

    // timestamp 변환 헬퍼 (chrono → microseconds)
    static int64_t toTimestamp(const std::chrono::system_clock::time_point& tp) {
        return std::chrono::duration_cast<std::chrono::microseconds>(tp.time_since_epoch()).count();
    }

    static double safeDouble(double v);

    void checkDailyRotation();
    void flushProcsToDBInternal();
    void flushSysToDBInternal();
    void flushTargetToDBInternal();
public:
    DataStore(size_t procCap = 120, size_t sysCap = 120, size_t targetCap = 120);
    ~DataStore() = default;

    void pushProcsData(const SnapshotProcData& data);
    void pushSysData(const SnapshotSysData& data);
    void pushTargetData(const SnapshotTargetData& data);


    void flushProcsToDB();
    void flushSysToDB();
    void flushTargetToDB();
    // 60초 주기 배치 flush 전용 — checkDailyRotation()을 1번만 호출한 뒤 세 스냅샷을 모두 flush한다.
    // 타겟 종료 시 즉시 flush하는 flushTargetToDB() 등 개별 호출 경로는 그대로 유지된다.
    void flushAllToDB();

    std::string getDbPath() const { return currentDbPath; }

    std::string queryReport(const std::string& sql);

    // 실시간 (RingBuffer → hot tier)
    std::vector<SnapshotSysData> getRecentSys(size_t n = 120) const;
    std::vector<SnapshotProcData> getRecentProcs(size_t n = 120) const;
    std::vector<SnapshotTargetData> getRecentTarget(size_t n = 120) const;

    // 과거 (DuckDB → cold tier)
    // hour: 0~23, 그 날짜(KST 기준) 중 해당 시(hour)의 데이터만 조회 (응답 크기/속도 제한용)
    // name: 프로세스/타겟은 이름 필수 지정 — 특정 이름 없이 그 시간대 전체를 훑는 조회는 허용하지 않음
    std::string querySysRangeJson(const std::string& date, int hour);
    std::string queryProcRangeJson(const std::string& date, const std::string& name, int hour);
    std::string queryTargetRangeJson(const std::string& date, const std::string& name, int hour);
    // 그 날짜에 기록이 있는 타겟/프로세스 이름 목록 (검색용 드롭다운)
    std::string getTargetNamesForDate(const std::string& date);
    std::string getProcNamesForDate(const std::string& date);

    size_t getProcsSize() const { return procsData.getSize(); }
    std::string getAvailableDates();

    template<typename Func>
    auto withConnection(Func&& func) {
        std::lock_guard<std::mutex> lock(dbMtx);
        checkDailyRotation();
        return func(con);
    }
};