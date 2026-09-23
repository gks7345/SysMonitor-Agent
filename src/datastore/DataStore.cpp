// DataStore.cpp
#include "datastore/DataStore.h"
#include "util/DateUtil.h"
#include <spdlog/spdlog.h>
#include <cctype>

DataStore::DataStore(size_t procCap, size_t sysCap, size_t targetCap)
    : procsData(procCap)
    , sysData(sysCap)
    , targetData(targetCap)
    , currentDbPath(makeDailyDbPath())
    , db(currentDbPath)  // 날짜 기반 파일명
    , con(db)

{
    initDB();
    spdlog::info("DB file location: {}", currentDbPath);  // ← 실제 경로 출력
}


// 오늘 날짜로 파일명 생성
std::string DataStore::makeDailyDbPath() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
    localtime_s(&tm, &time);

    char buf[64];
    strftime(buf, sizeof(buf), "reports/data/SysMonitor_data_%Y-%m-%d.db", &tm);

    // reports 폴더 생성
    std::filesystem::create_directories("reports/data");


    return std::string(buf);
}

bool DataStore::isValidDateFormat(const std::string& date) {
    if (date.size() != 10 || date[4] != '-' || date[7] != '-') return false;

    auto isDigits = [](const std::string& s) {
        for (char c : s) {
            if (!std::isdigit(static_cast<unsigned char>(c))) return false;
        }
        return true;
        };
    return isDigits(date.substr(0, 4)) && isDigits(date.substr(5, 2)) && isDigits(date.substr(8, 2));
}

void DataStore::checkDailyRotation() {
    std::string newPath = makeDailyDbPath();

    if (newPath == currentDbPath) return;

    // 날짜 바뀌면 새 파일로 교체
    flushProcsToDBInternal();
    flushSysToDBInternal();
    flushTargetToDBInternal();

    // 새 DB 연결
    db = duckdb::DuckDB(newPath);
    con = duckdb::Connection(db);
    initDB();
    currentDbPath = newPath;

    spdlog::info("DataStore: create new DBfile {}", newPath);
}

void DataStore::initDB() {
    // 시스템 테이블 — SnapShotSysData 구조 반영
    con.Query(R"(
        CREATE TABLE IF NOT EXISTS sys_snapshot (
            timestamp           BIGINT,
            diskTimestamp       BIGINT,
            cpuTotal            DOUBLE,
            cpuFreqGHz          DOUBLE,
            cpuUser             DOUBLE,
            cpuKernel           DOUBLE,
            cpuQueueLength      DOUBLE,
            memTotalMB          DOUBLE,
            memUsagePercent     DOUBLE,
            memUsedMB           DOUBLE,
            memAvailMB          DOUBLE,
            commitMemPercent    DOUBLE,
            committedMemGB      DOUBLE,
            commitLimitGB       DOUBLE,
            diskReadKBs         DOUBLE,
            diskWriteKBs        DOUBLE,
            netSentKbps         DOUBLE,
            netRecvKbps         DOUBLE
        )
    )");

    // 프로세스 테이블
    con.Query(R"(
        CREATE TABLE IF NOT EXISTS proc_snapshot (
            timestamp           BIGINT,
            topN                INTEGER,
            procID              INTEGER,
            procName            VARCHAR,
            procCpuUsage        DOUBLE,
            procMemoryMB        DOUBLE,
            procPrivateMemoryMB DOUBLE,
            procDiskReadMBs     DOUBLE,
            procDiskWriteMBs    DOUBLE,
            procNetSentMbps     DOUBLE,
            procNetRecvMbps     DOUBLE
        )
    )");

    // 타겟 프로세스 테이블
    // 메인 + 합계 테이블
    con.Query(R"(
        CREATE TABLE IF NOT EXISTS target_snapshot (
            timestamp           BIGINT,
            targetName          VARCHAR,
            exePath             VARCHAR,
            pid                 INTEGER,
            cpuUsage            DOUBLE,
            memoryMB            DOUBLE,
            privateMemoryMB     DOUBLE,
            virtualMemoryMB     DOUBLE,
            diskReadMBs         DOUBLE,
            diskWriteMBs        DOUBLE,
            netSentMbps         DOUBLE,
            netRecvMbps         DOUBLE,
            threadCount         INTEGER,
            handleCount         INTEGER,
            gdiObjectCount      INTEGER,
            pageFaultRate       DOUBLE,
            elapsedSec          DOUBLE,
            totalCpuUsage       DOUBLE,
            totalMemoryMB       DOUBLE,
            totalDiskMBs        DOUBLE,
            totalNetMbps        DOUBLE,
            totalThreadCount    INTEGER,
            totalHandleCount    INTEGER,
            totalProcessCount   INTEGER
        )
    )");

    // 자식 프로세스 테이블
    con.Query(R"(
        CREATE TABLE IF NOT EXISTS target_child_snapshot (
            timestamp           BIGINT,
            targetName          VARCHAR,
            pid                 INTEGER,
            processName         VARCHAR,
            cpuUsage            DOUBLE,
            memoryMB            DOUBLE,
            privateMemoryMB     DOUBLE,
            virtualMemoryMB     DOUBLE,
            diskReadMBs         DOUBLE,
            diskWriteMBs        DOUBLE,
            netSentMbps         DOUBLE,
            netRecvMbps         DOUBLE,
            threadCount         INTEGER,
            handleCount         INTEGER,
            gdiObjectCount      INTEGER,
            pageFaultRate       DOUBLE
        )
    )");

    // 네트워크 연결 테이블
    con.Query(R"(
        CREATE TABLE IF NOT EXISTS target_connection_snapshot (
            timestamp           BIGINT,
            targetName          VARCHAR,
            pid                 INTEGER,
            protocol            VARCHAR,
            localAddr           VARCHAR,
            remoteAddr          VARCHAR,
            state               VARCHAR
        )
    )");
}

void DataStore::pushProcsData(const SnapshotProcData& data) {
    std::unique_lock<std::shared_mutex> lock(procMtx);
    procsData.enQueue(data);
}

void DataStore::pushSysData(const SnapshotSysData& data) {
    std::unique_lock<std::shared_mutex> lock(sysMtx);
    sysData.enQueue(data);
}

void DataStore::pushTargetData(const SnapshotTargetData& data) {
    std::unique_lock<std::shared_mutex> lock(targetMtx);
    targetData.enQueue(data);
}

double DataStore::safeDouble(double v) {
    if (std::isnan(v) || std::isinf(v)) return 0.0;
    return v;
}

// SnapShotProcData → DuckDB
// SnapShotProcData.procs는 vector<SnapShotProc>이므로
// 하나의 스냅샷에서 여러 행 INSERT
void DataStore::flushProcsToDB() {
    std::lock_guard<std::mutex> lock(dbMtx);
    checkDailyRotation();
    flushProcsToDBInternal();
}

void DataStore::flushProcsToDBInternal() {
    std::vector<SnapshotProcData> items;
    {
        std::unique_lock<std::shared_mutex> lock(procMtx);
        items = procsData.peekNew();
    }

    if (items.empty()) return;

    duckdb::Appender appender(con, "proc_snapshot");

    int rowCount = 0;
    try {
        for (const auto& snap : items) {
            int64_t ts = toTimestamp(snap.timestamp);

            for (const auto& p : snap.procs) {
                appender.BeginRow();
                appender.Append(ts);
                appender.Append(static_cast<int32_t>(snap.topN));
                appender.Append(static_cast<int32_t>(p.procID));
                appender.Append(duckdb::string_t(p.procName));
                appender.Append(safeDouble(p.procCpuUsage));
                appender.Append(safeDouble(p.procMemoryMB));
                appender.Append(safeDouble(p.procPrivateMemoryMB));
                appender.Append(safeDouble(p.procDiskReadMBs));
                appender.Append(safeDouble(p.procDiskWriteMBs));
                appender.Append(safeDouble(p.procNetSentMbps));
                appender.Append(safeDouble(p.procNetRecvMbps));
                appender.EndRow();
                rowCount++;
            }
        }
        appender.Close();
    }
    catch (const duckdb::InvalidInputException& e) {
        spdlog::error("flushProcsToDB InvalidInput: {}", e.what());
    }
    catch (const std::exception& e) {
        spdlog::error("flushProcsToDB 예외: {}", e.what());
    }

    // 즉시 디스크에 반영
    con.Query("CHECKPOINT");
}

// SnapShotSysData → DuckDB
void DataStore::flushSysToDB() {
    std::lock_guard<std::mutex> lock(dbMtx);
    checkDailyRotation();
    flushSysToDBInternal();
}

void DataStore::flushSysToDBInternal() {
    std::vector<SnapshotSysData> items;
    {
        std::unique_lock<std::shared_mutex> lock(sysMtx);
        items = sysData.peekNew();
    }
    if (items.empty()) return;

    duckdb::Appender appender(con, "sys_snapshot");
    try {
        for (const auto& s : items) {
            appender.BeginRow();
            appender.Append(toTimestamp(s.timestamp));
            appender.Append(toTimestamp(s.disk.lastTime));

            // CPU
            appender.Append(safeDouble(s.cpu.cpuTotal));
            appender.Append(safeDouble(s.cpu.cpuFreqGHz));
            appender.Append(safeDouble(s.cpu.cpuUser));
            appender.Append(safeDouble(s.cpu.cpuKernel));
            appender.Append(safeDouble(s.cpu.cpuQueueLength));

            // MEM
            appender.Append(safeDouble(s.mem.memTotalMB));
            appender.Append(safeDouble(s.mem.memUsagePercent));
            appender.Append(safeDouble(s.mem.memUsedMB));
            appender.Append(safeDouble(s.mem.memAvailMB));
            appender.Append(safeDouble(s.mem.commitMemPercent));
            appender.Append(safeDouble(s.mem.committedMemGB));
            appender.Append(safeDouble(s.mem.commitLimitGB));

            // DISK
            appender.Append(safeDouble(s.disk.diskReadKBs));
            appender.Append(safeDouble(s.disk.diskWriteKBs));

            // NET
            appender.Append(safeDouble(s.net.netSentKbps));
            appender.Append(safeDouble(s.net.netRecvKbps));

            appender.EndRow();
        }
        appender.Close();
    }
    catch (const duckdb::InvalidInputException& e) {
        spdlog::error("flushSysToDB InvalidInput: {}", e.what());
    }
    catch (const std::exception& e) {
        spdlog::error("flushSysToDB 예외: {}", e.what());
    }

    // 즉시 디스크에 반영
    con.Query("CHECKPOINT");
}

void DataStore::flushTargetToDB() {
    std::lock_guard<std::mutex> lock(dbMtx);
    checkDailyRotation();
    flushTargetToDBInternal();
}

// 60초 주기 배치 flush 전용 진입점 — checkDailyRotation()을 1번만 호출한 뒤
// 세 스냅샷을 모두 flush한다. flushProcsToDB/flushSysToDB/flushTargetToDB를
// 각각 호출하면 checkDailyRotation()이 틱당 3번 중복 실행되기 때문에 이걸로 대체한다.
// 타겟 종료 시 즉시 flush하는 flushTargetToDB() 단독 호출 경로는 그대로 유지된다.
void DataStore::flushAllToDB() {
    std::lock_guard<std::mutex> lock(dbMtx);
    checkDailyRotation();
    flushProcsToDBInternal();
    flushSysToDBInternal();
    flushTargetToDBInternal();
}

void DataStore::flushTargetToDBInternal() {
    std::vector<SnapshotTargetData> items;
    {
        std::unique_lock<std::shared_mutex> lock(targetMtx);
        items = targetData.peekNew();
    }
    if (items.empty()) return;

    try {
        duckdb::Appender mainApp(con, "target_snapshot");
        duckdb::Appender childApp(con, "target_child_snapshot");
        duckdb::Appender connApp(con, "target_connection_snapshot");
        for (const auto& snap : items) {
            int64_t ts = toTimestamp(snap.timestamp);
            for (const auto& t : snap.targets) {
                // not_running/never_seen 항목은 실시간 API 표시용일 뿐 실제 수집 데이터가 아니므로
                // 영구 저장(DuckDB)에서는 제외 — 꺼져있던 시간대가 history 조회 시 gap으로 잡히도록 유지
                if (t.status != "running") continue;

                mainApp.BeginRow();
                mainApp.Append(ts);
                mainApp.Append(duckdb::string_t(t.targetName));
                mainApp.Append(duckdb::string_t(t.exePath));
                mainApp.Append(static_cast<int32_t>(t.pid));
                mainApp.Append(safeDouble(t.cpuUsage));
                mainApp.Append(safeDouble(t.memoryMB));
                mainApp.Append(safeDouble(t.privateMemoryMB));
                mainApp.Append(safeDouble(t.virtualMemoryMB));
                mainApp.Append(safeDouble(t.diskReadMBs));
                mainApp.Append(safeDouble(t.diskWriteMBs));
                mainApp.Append(safeDouble(t.netSentMbps));
                mainApp.Append(safeDouble(t.netRecvMbps));
                mainApp.Append(static_cast<int32_t>(t.threadCount));
                mainApp.Append(static_cast<int32_t>(t.handleCount));
                mainApp.Append(static_cast<int32_t>(t.gdiObjectCount));
                mainApp.Append(safeDouble(t.pageFaultRate));
                mainApp.Append(safeDouble(t.elapsedSec));
                mainApp.Append(safeDouble(t.totalCpuUsage));
                mainApp.Append(safeDouble(t.totalMemoryMB));
                mainApp.Append(safeDouble(t.totalDiskMBs));
                mainApp.Append(safeDouble(t.totalNetMbps));
                mainApp.Append(static_cast<int32_t>(t.totalThreadCount));
                mainApp.Append(static_cast<int32_t>(t.totalHandleCount));
                mainApp.Append(static_cast<int32_t>(t.totalProcessCount));
                mainApp.EndRow();

                // 메인 네트워크 연결
                for (const auto& conn : t.connections) {
                    connApp.BeginRow();
                    connApp.Append(ts);
                    connApp.Append(duckdb::string_t(t.targetName));
                    connApp.Append(static_cast<int32_t>(t.pid));
                    connApp.Append(duckdb::string_t(conn.protocol));
                    connApp.Append(duckdb::string_t(conn.localAddr));
                    connApp.Append(duckdb::string_t(conn.remoteAddr));
                    connApp.Append(duckdb::string_t(conn.state));
                    connApp.EndRow();
                }

                // 자식 프로세스
                for (const auto& c : t.children) {
                    childApp.BeginRow();
                    childApp.Append(ts);
                    childApp.Append(duckdb::string_t(t.targetName));
                    childApp.Append(static_cast<int32_t>(c.pid));
                    childApp.Append(duckdb::string_t(c.processName));
                    childApp.Append(safeDouble(c.cpuUsage));
                    childApp.Append(safeDouble(c.memoryMB));
                    childApp.Append(safeDouble(c.privateMemoryMB));
                    childApp.Append(safeDouble(c.virtualMemoryMB));
                    childApp.Append(safeDouble(c.diskReadMBs));
                    childApp.Append(safeDouble(c.diskWriteMBs));
                    childApp.Append(safeDouble(c.netSentMbps));
                    childApp.Append(safeDouble(c.netRecvMbps));
                    childApp.Append(static_cast<int32_t>(c.threadCount));
                    childApp.Append(static_cast<int32_t>(c.handleCount));
                    childApp.Append(static_cast<int32_t>(c.gdiObjectCount));
                    childApp.Append(safeDouble(c.pageFaultRate));
                    childApp.EndRow();

                    // 자식 네트워크 연결
                    for (const auto& conn : c.connections) {
                        connApp.BeginRow();
                        connApp.Append(ts);
                        connApp.Append(duckdb::string_t(t.targetName));
                        connApp.Append(static_cast<int32_t>(c.pid));
                        connApp.Append(duckdb::string_t(conn.protocol));
                        connApp.Append(duckdb::string_t(conn.localAddr));
                        connApp.Append(duckdb::string_t(conn.remoteAddr));
                        connApp.Append(duckdb::string_t(conn.state));
                        connApp.EndRow();
                    }
                }
            }
        }

        mainApp.Close();
        childApp.Close();
        connApp.Close();
        con.Query("CHECKPOINT");
    }
    catch (const std::exception& e) {
        spdlog::error("flushTargetToDB exception: {}", e.what());
    }
}

// -------------------------------------------------------
// 실시간 — RingBuffer에서 최근 N개 조회 (비파괴적)
// latest()는 deQueue하지 않고 읽기만 함
// -------------------------------------------------------
std::vector<SnapshotSysData> DataStore::getRecentSys(size_t n) const {
    std::shared_lock<std::shared_mutex> lock(sysMtx);
    return sysData.latest(n);
}

std::vector<SnapshotProcData> DataStore::getRecentProcs(size_t n) const {
    std::shared_lock<std::shared_mutex> lock(procMtx);
    return procsData.latest(n);
}

std::vector<SnapshotTargetData> DataStore::getRecentTarget(size_t n) const {
    std::shared_lock<std::shared_mutex> lock(targetMtx);
    return targetData.latest(n);
}

// -------------------------------------------------------
// 과거 — DuckDB 시간범위 조회 공통 헬퍼
// -------------------------------------------------------

// 날짜 범위 내 DB 파일 목록 반환
// "reports/data/SysMonitor_data_2026-06-27.db" 형식
std::string DataStore::getDbFilePath(const std::string& date) {
    std::string file = "";
    std::string dir = "reports/data/";

    if (!std::filesystem::exists(dir)) return file;

    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        std::string filename = entry.path().filename().string();
        // "SysMonitor_data_2026-06-27.db" -> 길이 최소 26자
        if (filename.size() < 26) continue;
        if (filename.substr(0, 16) != "SysMonitor_data_") continue;
        if (filename.substr(filename.size() - 3) != ".db") continue;

        std::string fileDate = filename.substr(16, 10); // "2026-06-27"
        if (fileDate == date)
            return entry.path().string();
    }
    return file;
}

std::string DataStore::getAvailableDates() {
    std::string dir = "reports/data/";
    nlohmann::json files = nlohmann::json::array();

    if (!std::filesystem::exists(dir)) return "[]";

    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        std::string filename = entry.path().filename().string();
        // "SysMonitor_data_2026-06-27.db" -> 길이 최소 26자
        if (filename.size() < 26) continue;
        if (filename.substr(0, 16) != "SysMonitor_data_") continue;
        if (filename.substr(filename.size() - 3) != ".db") continue;

        std::string fileDate = filename.substr(16, 10); // "2026-06-27"
        files.push_back(fileDate);
    }
    std::sort(files.begin(), files.end());
    return files.dump();
}

// 오늘 : con에서 읽어오기
// 과거 : ATTACH -> 쿼리 ->  DETACH 공통 처리
// rowMapper: DataChunk 한 행을 json으로 변환하는 람다
std::string DataStore::attachAndQuery(const std::string& date, const std::string& tableSql, duckdb::vector<duckdb::Value> params, std::function<nlohmann::json(duckdb::DataChunk*, size_t)> rowMapper) {
    if (!isValidDateFormat(date)) {
        spdlog::error("DataStore::attachAndQuery invalid date format: {}", date);
        return nlohmann::json({
            {"hasData", false},
            {"date",    date},
            {"gaps",    nlohmann::json::array()},
            {"data",    nlohmann::json::array()}
            }).dump();
    }
    return withConnection([&, date, tableSql, params, rowMapper](duckdb::Connection& con) -> std::string {
        bool isToday = (date == DateUtil::today());
        nlohmann::json arr = nlohmann::json::array();
        std::string attachName = "db_" + date.substr(0, 4) + date.substr(5, 2) + date.substr(8, 2);

        auto runQuery = [&](const std::string& sql) {
            auto stmt = con.Prepare(sql);
            if (stmt->HasError()) {
                spdlog::error("DataStore::attachAndQuery prepare: {}", stmt->GetError());
                return;
            }
            auto boundParams = params;
            auto r = stmt->Execute(boundParams);
            if (!r->HasError()) {
                auto chunk = r->Fetch();
                while (chunk) {
                    for (size_t i = 0; i < chunk->size(); ++i)
                        arr.push_back(rowMapper(chunk.get(), i));
                    chunk = r->Fetch();
                }
            }
            else {
                spdlog::error("DataStore::attachAndQuery query: {}", r->GetError());
            }
            };

        if (isToday) {
            // 오늘 날짜 -> 이미 열려있는 con 그대로 사용
            // {db}. 접두사 제거 후 직접 쿼리
            std::string sql = tableSql;
            size_t pos = 0;
            while ((pos = sql.find("{db}.", pos)) != std::string::npos)
                sql.erase(pos, 5);  // "{db}." 제거
            // {db} 만 남은 경우도 처리
            pos = 0;
            while ((pos = sql.find("{db}", pos)) != std::string::npos)
                sql.erase(pos, 4);

            runQuery(sql);

        }
        else {
            // 과거 날짜 -> ATTACH
            auto file = getDbFilePath(date);
            if (file.empty()) {
                return nlohmann::json({
                    {"hasData", false},
                    {"date",    date},
                    {"gaps",    nlohmann::json::array()},
                    {"data",    nlohmann::json::array()}
                    }).dump();
            }

            try {
                con.Query("ATTACH '" + file + "' AS " + attachName + " (READ_ONLY)");

                // tableSql 안의 {db}를 실제 attachName으로 치환
                std::string sql = tableSql;
                size_t pos = 0;
                while ((pos = sql.find("{db}", pos)) != std::string::npos) {
                    sql.replace(pos, 4, attachName);
                    pos += attachName.size();
                }

                runQuery(sql);

                con.Query("DETACH " + attachName);
            }
            catch (const std::exception& e) {
                spdlog::error("DataStore::attachAndQuery exception: {}", e.what());
                try { con.Query("DETACH " + attachName); }
                catch (...) {}
            }
        }

        // gap 계산 (5초 이상 공백 → 프로그램 꺼진 시간)
        nlohmann::json gaps = nlohmann::json::array();
        for (size_t i = 1; i < arr.size(); ++i) {
            int64_t prev = arr[i - 1]["timestamp"].get<int64_t>();
            int64_t curr = arr[i]["timestamp"].get<int64_t>();
            if (curr - prev > 5000)
                gaps.push_back({ {"from", prev}, {"to", curr} });
        }

        return nlohmann::json({
            {"hasData", !arr.empty()},
            {"date",    date},
            {"gaps",    gaps},
            {"data",    arr}
            }).dump();
        });
}


// -------------------------------------------------------
// 시스템 — 날짜별 조회
// -------------------------------------------------------
std::string DataStore::querySysRangeJson(const std::string& date, int hour) {
    std::string sql =
        "SELECT CAST(timestamp AS BIGINT), "
        "  cpuTotal, cpuFreqGHz, "
        "  memUsagePercent, memUsedMB, memTotalMB, memAvailMB, "
        "  diskReadKBs, diskWriteKBs, "
        "  netSentKbps, netRecvKbps "
        "FROM {db}.sys_snapshot "
        "WHERE EXTRACT(HOUR FROM epoch_ms(CAST((CAST(timestamp AS BIGINT) + 32400000000) / 1000 AS BIGINT))) = ? "
        "ORDER BY timestamp ASC";

    return attachAndQuery(date, sql, { duckdb::Value::INTEGER(hour) },
        [](duckdb::DataChunk* chunk, size_t i) -> nlohmann::json {
            return {
                    {"timestamp",       std::stoll(chunk->GetValue(0, i).ToString()) / 1000},
                    {"cpuTotal",        std::stod(chunk->GetValue(1, i).ToString())},
                    {"cpuFreqGHz",      std::stod(chunk->GetValue(2, i).ToString())},
                    {"memUsagePercent", std::stod(chunk->GetValue(3, i).ToString())},
                    {"memUsedMB",       std::stod(chunk->GetValue(4, i).ToString())},
                    {"memTotalMB",      std::stod(chunk->GetValue(5, i).ToString())},
                    {"memAvailMB",      std::stod(chunk->GetValue(6, i).ToString())},
                    {"diskReadKBs",     std::stod(chunk->GetValue(7, i).ToString())},
                    {"diskWriteKBs",    std::stod(chunk->GetValue(8, i).ToString())},
                    {"netSentKbps",     std::stod(chunk->GetValue(9, i).ToString())},
                    {"netRecvKbps",     std::stod(chunk->GetValue(10, i).ToString())}
            };
        });
}

// -------------------------------------------------------
// 프로세스 — 날짜 + 이름(필수) + 시(hour) 조회
// -------------------------------------------------------
std::string DataStore::queryProcRangeJson(const std::string& date, const std::string& name, int hour) {
    std::string sql =
        "SELECT CAST(timestamp AS BIGINT), "
        "  procName, procID, "
        "  procCpuUsage, procMemoryMB, procPrivateMemoryMB, "
        "  procDiskReadMBs, procDiskWriteMBs, "
        "  procNetSentMbps, procNetRecvMbps "
        "FROM {db}.proc_snapshot "
        "WHERE procName = ? "
        "AND EXTRACT(HOUR FROM epoch_ms(CAST((CAST(timestamp AS BIGINT) + 32400000000) / 1000 AS BIGINT))) = ?"
        " ORDER BY timestamp ASC, procCpuUsage DESC";

    return attachAndQuery(date, sql, { duckdb::Value(name), duckdb::Value::INTEGER(hour) }, [](duckdb::DataChunk* chunk, size_t i) -> nlohmann::json {
        return {
                {"timestamp",       std::stoll(chunk->GetValue(0, i).ToString()) / 1000},
                {"procName",        chunk->GetValue(1, i).ToString()},
                {"procID",          std::stoul(chunk->GetValue(2, i).ToString())},
                {"cpuUsage",        std::stod(chunk->GetValue(3, i).ToString())},
                {"memoryMB",        std::stod(chunk->GetValue(4, i).ToString())},
                {"privateMemoryMB", std::stod(chunk->GetValue(5, i).ToString())},
                {"diskReadMBs",     std::stod(chunk->GetValue(6, i).ToString())},
                {"diskWriteMBs",    std::stod(chunk->GetValue(7, i).ToString())},
                {"netSentMbps",     std::stod(chunk->GetValue(8, i).ToString())},
                {"netRecvMbps",     std::stod(chunk->GetValue(9, i).ToString())}
        };
        });
}

// -------------------------------------------------------
// 타겟 — 날짜별 조회 (전체 컬럼 + 자식 + 연결)
// attachAndQuery 대신 직접 구현 (JOIN이 필요하므로)
// -------------------------------------------------------
std::string DataStore::queryTargetRangeJson(const std::string& date, const std::string& name, int hour) {
    if (!isValidDateFormat(date)) {
        spdlog::error("DataStore::queryTargetRangeJson invalid date format: {}", date);
        return "[]";
    }
    return withConnection([&, date, name, hour](duckdb::Connection& con) -> std::string {
        std::string today = DateUtil::today();
        bool isToday = (date == today);

        // 테이블 접두사 — 오늘이면 현재 DB, 과거면 ATTACH
        std::string dbPrefix = "";
        std::string attachName = "";

        if (!isToday) {
            auto file = getDbFilePath(date);
            if (file.empty()) {
                return nlohmann::json({
                    {"hasData", false},
                    {"date",    date},
                    {"gaps",    nlohmann::json::array()},
                    {"data",    nlohmann::json::array()}
                    }).dump();
            }
            attachName = "db_"
                + date.substr(0, 4)
                + date.substr(5, 2)
                + date.substr(8, 2);
            con.Query("ATTACH '" + file + "' AS "
                + attachName + " (READ_ONLY)");
            dbPrefix = attachName + ".";
        }

        std::string hourExpr = "EXTRACT(HOUR FROM epoch_ms(CAST((CAST(timestamp AS BIGINT) + 32400000000) / 1000 AS BIGINT))) = ?";

        try {
            // 메인 타겟 snapshot 조회 — targetName(필수) + hour(필수)
            std::string mainSql =
                "SELECT CAST(t.timestamp AS BIGINT), "
                "  t.targetName, t.exePath, t.pid, "
                "  t.cpuUsage, t.memoryMB, t.privateMemoryMB, t.virtualMemoryMB, "
                "  t.diskReadMBs, t.diskWriteMBs, "
                "  t.netSentMbps, t.netRecvMbps, "
                "  t.threadCount, t.handleCount, t.gdiObjectCount, t.pageFaultRate, "
                "  t.elapsedSec, "
                "  t.totalCpuUsage, t.totalMemoryMB, t.totalDiskMBs, t.totalNetMbps, "
                "  t.totalThreadCount, t.totalHandleCount, t.totalProcessCount "
                "FROM " + dbPrefix + "target_snapshot t "
                "WHERE t.targetName = ? "
                "AND EXTRACT(HOUR FROM epoch_ms(CAST((CAST(t.timestamp AS BIGINT) + 32400000000) / 1000 AS BIGINT))) = ?"
                " ORDER BY t.timestamp ASC";

            auto mainStmt = con.Prepare(mainSql);
            if (mainStmt->HasError()) {
                spdlog::error("queryTargetRangeJson main prepare: {}", mainStmt->GetError());
                if (!isToday) con.Query("DETACH " + attachName);
                return "[]";
            }
            auto r = mainStmt->Execute(name, hour);
            if (r->HasError()) {
                spdlog::error("queryTargetRangeJson main: {}", r->GetError());
                if (!isToday) con.Query("DETACH " + attachName);
                return "[]";
            }

            // timestamp별 메인 데이터 수집
            // key: "targetName_timestamp" → json
            std::vector<nlohmann::json> arr;
            std::map<std::string, size_t> indexMap;  // key → arr 인덱스

            auto chunk = r->Fetch();
            while (chunk) {
                for (size_t i = 0; i < chunk->size(); ++i) {
                    int64_t ts = std::stoll(chunk->GetValue(0, i).ToString());
                    std::string tName = chunk->GetValue(1, i).ToString();
                    std::string key = tName + "_" + std::to_string(ts);

                    nlohmann::json entry = {
                        {"timestamp",        ts / 1000},
                        {"targetName",       tName},
                        {"exePath",          chunk->GetValue(2, i).ToString()},
                        {"pid",              std::stoul(chunk->GetValue(3, i).ToString())},
                        {"cpuUsage",         std::stod(chunk->GetValue(4, i).ToString())},
                        {"memoryMB",         std::stod(chunk->GetValue(5, i).ToString())},
                        {"privateMemoryMB",  std::stod(chunk->GetValue(6, i).ToString())},
                        {"virtualMemoryMB",  std::stod(chunk->GetValue(7, i).ToString())},
                        {"diskReadMBs",      std::stod(chunk->GetValue(8, i).ToString())},
                        {"diskWriteMBs",     std::stod(chunk->GetValue(9, i).ToString())},
                        {"netSentMbps",      std::stod(chunk->GetValue(10, i).ToString())},
                        {"netRecvMbps",      std::stod(chunk->GetValue(11, i).ToString())},
                        {"threadCount",      std::stoul(chunk->GetValue(12, i).ToString())},
                        {"handleCount",      std::stoul(chunk->GetValue(13, i).ToString())},
                        {"gdiObjectCount",   std::stoul(chunk->GetValue(14, i).ToString())},
                        {"pageFaultRate",    std::stod(chunk->GetValue(15, i).ToString())},
                        {"elapsedSec",       std::stod(chunk->GetValue(16, i).ToString())},
                        {"totalCpuUsage",    std::stod(chunk->GetValue(17, i).ToString())},
                        {"totalMemoryMB",    std::stod(chunk->GetValue(18, i).ToString())},
                        {"totalDiskMBs",     std::stod(chunk->GetValue(19, i).ToString())},
                        {"totalNetMbps",     std::stod(chunk->GetValue(20, i).ToString())},
                        {"totalThreadCount", std::stoul(chunk->GetValue(21, i).ToString())},
                        {"totalHandleCount", std::stoul(chunk->GetValue(22, i).ToString())},
                        {"totalProcessCount",std::stoul(chunk->GetValue(23, i).ToString())},
                        {"children",         nlohmann::json::array()},
                        {"connections",      nlohmann::json::array()}
                    };

                    indexMap[key] = arr.size();
                    arr.push_back(std::move(entry));
                }
                chunk = r->Fetch();
            }

            // 자식 프로세스 snapshot 조회
            std::string childSql =
                "SELECT CAST(timestamp AS BIGINT), "
                "  targetName, pid, processName, "
                "  cpuUsage, memoryMB, privateMemoryMB, virtualMemoryMB, "
                "  diskReadMBs, diskWriteMBs, "
                "  netSentMbps, netRecvMbps, "
                "  threadCount, handleCount, gdiObjectCount, pageFaultRate "
                "FROM " + dbPrefix + "target_child_snapshot "
                "WHERE targetName = ? AND " + hourExpr +
                " ORDER BY timestamp ASC";

            auto childStmt = con.Prepare(childSql);
            auto rc = childStmt->HasError() ? nullptr : childStmt->Execute(name, hour);
            if (rc && !rc->HasError()) {
                auto cc = rc->Fetch();
                while (cc) {
                    for (size_t i = 0; i < cc->size(); ++i) {
                        int64_t ts = std::stoll(cc->GetValue(0, i).ToString());
                        std::string tName = cc->GetValue(1, i).ToString();
                        std::string key = tName + "_" + std::to_string(ts);

                        auto it = indexMap.find(key);
                        if (it == indexMap.end()) continue;

                        arr[it->second]["children"].push_back({
                            {"pid",            std::stoul(cc->GetValue(2, i).ToString())},
                            {"processName",    cc->GetValue(3, i).ToString()},
                            {"cpuUsage",       std::stod(cc->GetValue(4, i).ToString())},
                            {"memoryMB",       std::stod(cc->GetValue(5, i).ToString())},
                            {"privateMemoryMB",std::stod(cc->GetValue(6, i).ToString())},
                            {"virtualMemoryMB",std::stod(cc->GetValue(7, i).ToString())},
                            {"diskReadMBs",    std::stod(cc->GetValue(8, i).ToString())},
                            {"diskWriteMBs",   std::stod(cc->GetValue(9, i).ToString())},
                            {"netSentMbps",    std::stod(cc->GetValue(10, i).ToString())},
                            {"netRecvMbps",    std::stod(cc->GetValue(11, i).ToString())},
                            {"threadCount",    std::stoul(cc->GetValue(12, i).ToString())},
                            {"handleCount",    std::stoul(cc->GetValue(13, i).ToString())},
                            {"gdiObjectCount", std::stoul(cc->GetValue(14, i).ToString())},
                            {"pageFaultRate",  std::stod(cc->GetValue(15, i).ToString())}
                            });
                    }
                    cc = rc->Fetch();
                }
            }

            // 네트워크 연결 snapshot 조회
            std::string connSql =
                "SELECT CAST(timestamp AS BIGINT), "
                "  targetName, pid, protocol, "
                "  localAddr, remoteAddr, state "
                "FROM " + dbPrefix + "target_connection_snapshot "
                "WHERE targetName = ? AND " + hourExpr +
                " ORDER BY timestamp ASC";

            auto connStmt = con.Prepare(connSql);
            auto rn = connStmt->HasError() ? nullptr : connStmt->Execute(name, hour);
            if (rn && !rn->HasError()) {
                auto cn = rn->Fetch();
                while (cn) {
                    for (size_t i = 0; i < cn->size(); ++i) {
                        int64_t ts = std::stoll(cn->GetValue(0, i).ToString());
                        std::string tName = cn->GetValue(1, i).ToString();
                        std::string key = tName + "_" + std::to_string(ts);

                        auto it = indexMap.find(key);
                        if (it == indexMap.end()) continue;

                        arr[it->second]["connections"].push_back({
                            {"pid",        std::stoul(cn->GetValue(2, i).ToString())},
                            {"protocol",   cn->GetValue(3, i).ToString()},
                            {"localAddr",  cn->GetValue(4, i).ToString()},
                            {"remoteAddr", cn->GetValue(5, i).ToString()},
                            {"state",      cn->GetValue(6, i).ToString()}
                            });
                    }
                    cn = rn->Fetch();
                }
            }

            if (!isToday) con.Query("DETACH " + attachName);

            // gap 계산 (5초 이상 공백)
            nlohmann::json gaps = nlohmann::json::array();
            for (size_t i = 1; i < arr.size(); ++i) {
                int64_t prev = arr[i - 1]["timestamp"].get<int64_t>();
                int64_t curr = arr[i]["timestamp"].get<int64_t>();
                if (curr - prev > 5000)
                    gaps.push_back({ {"from", prev}, {"to", curr} });
            }

            nlohmann::json result = arr;
            return nlohmann::json({
                {"hasData", !arr.empty()},
                {"date",    date},
                {"gaps",    gaps},
                {"data",    result}
                }).dump();

        }
        catch (const std::exception& e) {
            spdlog::error("queryTargetRangeJson exception: {}", e.what());
            if (!isToday && !attachName.empty())
                try { con.Query("DETACH " + attachName); }
            catch (...) {}
            return nlohmann::json({
                {"hasData", false},
                {"date",    date},
                {"gaps",    nlohmann::json::array()},
                {"data",    nlohmann::json::array()}
                }).dump();
        }
        });
}

// -------------------------------------------------------
// 타겟 — 그 날짜에 기록이 있는 타겟 이름 목록 (검색 드롭다운용)
// -------------------------------------------------------
std::string DataStore::getTargetNamesForDate(const std::string& date) {
    if (!isValidDateFormat(date)) {
        spdlog::error("DataStore::getTargetNamesForDate invalid date format: {}", date);
        return "[]";
    }
    return withConnection([&, date](duckdb::Connection& con) -> std::string {
        bool isToday = (date == DateUtil::today());
        std::string dbPrefix = "";
        std::string attachName = "";

        if (!isToday) {
            auto file = getDbFilePath(date);
            if (file.empty()) return "[]";
            attachName = "db_" + date.substr(0, 4) + date.substr(5, 2) + date.substr(8, 2);
            con.Query("ATTACH '" + file + "' AS " + attachName + " (READ_ONLY)");
            dbPrefix = attachName + ".";
        }

        nlohmann::json arr = nlohmann::json::array();
        auto r = con.Query("SELECT DISTINCT targetName FROM " + dbPrefix + "target_snapshot ORDER BY targetName");
        if (!r->HasError()) {
            auto chunk = r->Fetch();
            while (chunk) {
                for (size_t i = 0; i < chunk->size(); ++i)
                    arr.push_back(chunk->GetValue(0, i).ToString());
                chunk = r->Fetch();
            }
        }
        else {
            spdlog::error("DataStore::getTargetNamesForDate: {}", r->GetError());
        }

        if (!isToday) con.Query("DETACH " + attachName);
        return arr.dump();
        });
}

// -------------------------------------------------------
// 프로세스 — 그 날짜에 기록이 있는 프로세스 이름 목록 (검색 드롭다운용)
// -------------------------------------------------------
std::string DataStore::getProcNamesForDate(const std::string& date) {
    if (!isValidDateFormat(date)) {
        spdlog::error("DataStore::getProcNamesForDate invalid date format: {}", date);
        return "[]";
    }
    return withConnection([&, date](duckdb::Connection& con) -> std::string {
        bool isToday = (date == DateUtil::today());
        std::string dbPrefix = "";
        std::string attachName = "";

        if (!isToday) {
            auto file = getDbFilePath(date);
            if (file.empty()) return "[]";
            attachName = "db_" + date.substr(0, 4) + date.substr(5, 2) + date.substr(8, 2);
            con.Query("ATTACH '" + file + "' AS " + attachName + " (READ_ONLY)");
            dbPrefix = attachName + ".";
        }

        nlohmann::json arr = nlohmann::json::array();
        auto r = con.Query("SELECT DISTINCT procName FROM " + dbPrefix + "proc_snapshot ORDER BY procName");
        if (!r->HasError()) {
            auto chunk = r->Fetch();
            while (chunk) {
                for (size_t i = 0; i < chunk->size(); ++i)
                    arr.push_back(chunk->GetValue(0, i).ToString());
                chunk = r->Fetch();
            }
        }
        else {
            spdlog::error("DataStore::getProcNamesForDate: {}", r->GetError());
        }

        if (!isToday) con.Query("DETACH " + attachName);
        return arr.dump();
        });
}


std::string DataStore::queryReport(const std::string& sql) {
    std::lock_guard<std::mutex> lock(dbMtx);
    auto result = con.Query(sql);
    if (result->HasError()) {
        spdlog::error("DataStore: query error {}", result->GetError());
        return "";
    }
    return result->ToString();
}

