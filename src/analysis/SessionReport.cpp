#include "analysis/SessionReport.h"
#include "Config.h"


SessionReport::SessionReport(DataStore& dataStore) :dataStore(dataStore) {}

double SessionReport::safeStod(const std::string& s) {
    try { return std::stod(s); }
    catch (...) { return 0.0; }
}

int SessionReport::safeStoi(const std::string& s) {
    try { return std::stoi(s); }
    catch (...) { return 0; }
}

// -------------------------------------------------------
// 시스템 분석
// -------------------------------------------------------
SessionSysSummary SessionReport::analyzeSys() {
    std::string date = DateUtil::today();
    return dataStore.withConnection([date](duckdb::Connection& con)->SessionSysSummary {
        SessionSysSummary result;



        std::string sql = "SELECT"
            "   ROUND(AVG(cpuTotal),    2) AS avgCpu,"
            "   ROUND(MAX(cpuTotal),    2) AS peakCpu,"
            "   ROUND(AVG(memUsagePercent), 2) AS avgMem,"
            "   ROUND(MAX(memUsagePercent), 2) AS peakMem,"
            "   ROUND(AVG(diskReadKBs + diskWriteKBs), 2) AS avgDisk,"
            "   ROUND(MAX(diskReadKBs + diskWriteKBs), 2) AS peakDisk,"
            "   ROUND(AVG(netSentKbps + netRecvKbps),  2) AS avgNet,"
            "   ROUND(MAX(netSentKbps + netRecvKbps),  2) AS peakNet,"
            "COUNT(*) AS samples "
            "FROM sys_snapshot "
            "WHERE CAST(epoch_ms(CAST((CAST(timestamp AS BIGINT) + 32400000000) / 1000 AS BIGINT)) AS DATE) = CAST(? AS DATE) ";

        auto stmt = con.Prepare(sql);
        if (stmt->HasError()) {
            spdlog::error("SessionReport: analyzeSys prepare: {}", stmt->GetError());
            return result;
        }
        // CAST(? AS DATE) 문맥만으로는 DuckDB가 ?의 타입을 제대로 추론 못 하고 BLOB으로
        // 잘못 판단해 "Unimplemented type for cast (BLOB -> DATE)" 에러를 내는 문제가 있어,
        // duckdb::Value로 명시적으로 VARCHAR 타입을 지정해 바인딩한다.
        auto r = stmt->Execute(duckdb::Value(date));

        if (r->HasError()) {
            spdlog::error("SessionReport: analyzeSys error: {}", r->GetError());
            return result;
        }
        auto chunk = r->Fetch();
        if (!chunk || chunk->size() == 0) return result;
        result.date = date;
        result.avgCpuTotal = safeStod(chunk->GetValue(0, 0).ToString());
        result.peakCpuTotal = safeStod(chunk->GetValue(1, 0).ToString());
        result.avgMemUsagePercent = safeStod(chunk->GetValue(2, 0).ToString());
        result.peakMemUsagePercent = safeStod(chunk->GetValue(3, 0).ToString());
        result.avgDiskKBs = safeStod(chunk->GetValue(4, 0).ToString());
        result.peakDiskKBs = safeStod(chunk->GetValue(5, 0).ToString());
        result.avgNetKbps = safeStod(chunk->GetValue(6, 0).ToString());
        result.peakNetKbps = safeStod(chunk->GetValue(7, 0).ToString());
        result.sampleCount = safeStoi(chunk->GetValue(8, 0).ToString());

        return result;
        });
}

// -------------------------------------------------------
// 프로세스 분석
// -------------------------------------------------------
std::vector<SessionProcSummary> SessionReport::analyzeProcs(int topN) {
    std::string date = DateUtil::today();
    return dataStore.withConnection([date, topN](duckdb::Connection& con)-> std::vector<SessionProcSummary> {
        std::vector<SessionProcSummary> result;

        std::string sql =
            "SELECT procName, "
            "  ROUND(AVG(procCpuUsage), 2) AS avgCpu, "
            "  ROUND(MAX(procCpuUsage), 2) AS peakCpu, "
            "  ROUND(AVG(procMemoryMB), 2) AS avgMem, "
            "  ROUND(MAX(procMemoryMB), 2) AS peakMem, "
            "  ROUND(AVG(procDiskReadMBs + procDiskWriteMBs), 2) AS avgDisk, "
            "  ROUND(MAX(procDiskReadMBs + procDiskWriteMBs), 2) AS peakDisk, "
            "  ROUND(AVG(procNetSentMbps + procNetRecvMbps), 2) AS avgNet, "
            "  ROUND(MAX(procNetSentMbps + procNetRecvMbps), 2) AS peakNet, "
            "  COUNT(*) AS samples "
            "FROM proc_snapshot "
            "WHERE CAST(epoch_ms(CAST((CAST(timestamp AS BIGINT) + 32400000000) / 1000 AS BIGINT)) AS DATE) = CAST(? AS DATE) "
            "GROUP BY procName "
            "ORDER BY avgCpu DESC";
        if (topN > 0) {
            sql += " LIMIT " + std::to_string(topN);
        }

        auto stmt = con.Prepare(sql);
        if (stmt->HasError()) {
            spdlog::error("SessionReport: analyzeProcs prepare: {}", stmt->GetError());
            return result;
        }
        // CAST(? AS DATE) 문맥만으로는 DuckDB가 ?의 타입을 제대로 추론 못 하고 BLOB으로
        // 잘못 판단해 "Unimplemented type for cast (BLOB -> DATE)" 에러를 내는 문제가 있어,
        // duckdb::Value로 명시적으로 VARCHAR 타입을 지정해 바인딩한다.
        auto r = stmt->Execute(duckdb::Value(date));
        if (r->HasError()) {
            spdlog::error("SessionReport: analyzeProcs error: {}", r->GetError());
            return result;
        }
        auto chunk = r->Fetch();
        while (chunk) {
            for (size_t i = 0; i < chunk->size(); ++i) {
                SessionProcSummary p;
                p.date = date;
                p.procName = chunk->GetValue(0, i).ToString();
                p.avgCpuUsage = safeStod(chunk->GetValue(1, i).ToString());
                p.peakCpuUsage = safeStod(chunk->GetValue(2, i).ToString());
                p.avgMemoryMB = safeStod(chunk->GetValue(3, i).ToString());
                p.peakMemoryMB = safeStod(chunk->GetValue(4, i).ToString());
                p.avgDiskMBs = safeStod(chunk->GetValue(5, i).ToString());
                p.peakDiskMBs = safeStod(chunk->GetValue(6, i).ToString());
                p.avgNetMbps = safeStod(chunk->GetValue(7, i).ToString());
                p.peakNetMbps = safeStod(chunk->GetValue(8, i).ToString());
                p.sampleCount = safeStoi(chunk->GetValue(9, i).ToString());
                result.push_back(std::move(p));
            }
            chunk = r->Fetch();
        }

        return result;
        });
}

// -------------------------------------------------------
// 타겟 분석
// -------------------------------------------------------
std::vector<SessionTargetSummary> SessionReport::analyzeTargets() {
    std::string date = DateUtil::today();
    return dataStore.withConnection([date](duckdb::Connection& con)-> std::vector<SessionTargetSummary> {
        std::vector<SessionTargetSummary> result;

        std::string sql =
            "SELECT "
            "    targetName, "
            "    MAX(exePath)                     AS exePath, "
            "    ROUND(AVG(totalCpuUsage), 2)     AS avgCpu, "
            "    ROUND(MAX(totalCpuUsage), 2)     AS peakCpu, "
            "    ROUND(AVG(totalMemoryMB), 2)     AS avgMem, "
            "    ROUND(MAX(totalMemoryMB), 2)     AS peakMem, "
            "    ROUND(AVG(totalNetMbps), 2)      AS avgNet, "
            "    ROUND(MAX(totalNetMbps), 2)      AS peakNet, "
            "    MAX(totalThreadCount)            AS peakThread, "
            "    MAX(totalHandleCount)            AS peakHandle, "
            "    ROUND(COUNT(*) * " + std::to_string(Config::MIDDLE_COLLECT_INTERVAL) + ", 1) AS runTime, "
            "    COUNT(*)                         AS samples "
            "FROM target_snapshot "
            "WHERE CAST(epoch_ms(CAST((CAST(timestamp AS BIGINT) + 32400000000) / 1000 AS BIGINT)) AS DATE) = CAST(? AS DATE) "
            "GROUP BY targetName";

        auto stmt = con.Prepare(sql);
        if (stmt->HasError()) {
            spdlog::error("SessionReport: analyzeTargets prepare: {}", stmt->GetError());
            return result;
        }

        auto r = stmt->Execute(duckdb::Value(date));

        if (r->HasError()) {
            spdlog::error("SessionReport: analyzeTargets error: {}", r->GetError());
            return result;
        }

        auto chunk = r->Fetch();
        while (chunk) {
            for (size_t i = 0; i < chunk->size(); ++i)
            {
                SessionTargetSummary t;
                t.date = date;
                t.targetName = chunk->GetValue(0, i).ToString();
                t.exePath = chunk->GetValue(1, i).ToString();
                t.avgCpuUsage = safeStod(chunk->GetValue(2, i).ToString());
                t.peakCpuUsage = safeStod(chunk->GetValue(3, i).ToString());
                t.avgMemoryMB = safeStod(chunk->GetValue(4, i).ToString());
                t.peakMemoryMB = safeStod(chunk->GetValue(5, i).ToString());
                t.avgNetMbps = safeStod(chunk->GetValue(6, i).ToString());
                t.peakNetMbps = safeStod(chunk->GetValue(7, i).ToString());
                t.peakThreadCount = static_cast<uint32_t>(std::stoul(chunk->GetValue(8, i).ToString()));
                t.peakHandleCount = static_cast<uint32_t>(std::stoul(chunk->GetValue(9, i).ToString()));
                t.runTime = safeStod(chunk->GetValue(10, i).ToString());
                t.sampleCount = safeStoi(chunk->GetValue(11, i).ToString());
                result.push_back(std::move(t));
            }
            chunk = r->Fetch();
        }
        return result;
        });
}

SessionTargetSummary SessionReport::getSessionTargetSummaryOne(const std::string& name) {
    std::string date = DateUtil::today();
    return dataStore.withConnection([name, date](duckdb::Connection& con)-> SessionTargetSummary {
        SessionTargetSummary result;

        auto stmt = con.Prepare(
            "SELECT "
            "    targetName, "
            "    MAX(exePath)                     AS exePath, "
            "    ROUND(AVG(totalCpuUsage), 2)     AS avgCpu, "
            "    ROUND(MAX(totalCpuUsage), 2)     AS peakCpu, "
            "    ROUND(AVG(totalMemoryMB), 2)     AS avgMem, "
            "    ROUND(MAX(totalMemoryMB), 2)     AS peakMem, "
            "    ROUND(AVG(totalNetMbps), 2)      AS avgNet, "
            "    ROUND(MAX(totalNetMbps), 2)      AS peakNet, "
            "    MAX(totalThreadCount)            AS peakThread, "
            "    MAX(totalHandleCount)            AS peakHandle, "
            "    ROUND(COUNT(*) * " + std::to_string(Config::MIDDLE_COLLECT_INTERVAL) + ", 1) AS runTime, "
            "    COUNT(*)                         AS samples "
            "FROM target_snapshot "
            "WHERE CAST(epoch_ms(CAST((CAST(timestamp AS BIGINT) + 32400000000) / 1000 AS BIGINT)) AS DATE) = CAST(? AS DATE) "
            "  AND targetName = ? "
            "GROUP BY targetName"
        );

        if (stmt->HasError()) {
            spdlog::error("getSessionTargetSummaryOne prepare: {}", stmt->GetError());
            return result;
        }

        auto r = stmt->Execute(duckdb::Value(date), name);
        if (r->HasError())
        {
            spdlog::error("getSessionTargetSummaryOne excute: {}", r->GetError());
            return result;
        }

        auto chunk = r->Fetch();
        if (!chunk || chunk->size() == 0) return result;
        // 단일 행만 읽기
        result.date = date;
        result.targetName = chunk->GetValue(0, 0).ToString();
        result.exePath = chunk->GetValue(1, 0).ToString();
        result.avgCpuUsage = safeStod(chunk->GetValue(2, 0).ToString());
        result.peakCpuUsage = safeStod(chunk->GetValue(3, 0).ToString());
        result.avgMemoryMB = safeStod(chunk->GetValue(4, 0).ToString());
        result.peakMemoryMB = safeStod(chunk->GetValue(5, 0).ToString());
        result.avgNetMbps = safeStod(chunk->GetValue(6, 0).ToString());
        result.peakNetMbps = safeStod(chunk->GetValue(7, 0).ToString());
        result.peakThreadCount = static_cast<uint32_t>(std::stoul(chunk->GetValue(8, 0).ToString()));
        result.peakHandleCount = static_cast<uint32_t>(std::stoul(chunk->GetValue(9, 0).ToString()));
        result.runTime = safeStod(chunk->GetValue(10, 0).ToString());
        result.sampleCount = safeStoi(chunk->GetValue(11, 0).ToString());

        return result;
        });
}

// -------------------------------------------------------
// 전체 출력
// -------------------------------------------------------
void SessionReport::printReport() {
    printf("\n+%s+\n", std::string(66, '=').c_str());
    printf("|%-66s|\n", "  SysMonitor Session Report");
    printf("+%s+\n", std::string(66, '=').c_str());

    auto sys = analyzeSys();
    auto procs = analyzeProcs(Config::DEFAULT_TOP_N);
    auto targets = analyzeTargets();

    printSysReport(sys);
    printProcReport(procs);
    printTargetReport(targets);
    printAnomalies();

    printf("+%s+\n", std::string(66, '=').c_str());
}

void SessionReport::printSysReport(const SessionSysSummary& s) {
    printf("\n[ System Summary ] (%d samples)\n", s.sampleCount);
    printf("  %-20s %8s %8s\n", "", "AVG", "PEAK");
    printf("  %-20s %7.1f%% %7.1f%%\n",
        "CPU", s.avgCpuTotal, s.peakCpuTotal);
    printf("  %-20s %7.1f%% %7.1f%%\n",
        "Memory", s.avgMemUsagePercent, s.peakMemUsagePercent);
    printf("  %-20s %6.1fKB/s %6.1fKB/s\n",
        "Disk", s.avgDiskKBs, s.peakDiskKBs);
    printf("  %-20s %5.1fKbps %5.1fKbps\n",
        "Network", s.avgNetKbps, s.peakNetKbps);
}

void SessionReport::printProcReport(
    const std::vector<SessionProcSummary>& procs) {
    printf("\n[ Process Top %zu ]\n", procs.size());
    printf("  %-20s %8s %8s %8s %8s\n",
        "Name", "avgCPU%", "peakCPU", "avgMem", "peakMem");
    printf("  %s\n", std::string(56, '-').c_str());
    for (const auto& p : procs) {
        std::string name = p.procName;
        if (name.size() > 19) name = name.substr(0, 16) + "...";
        printf("  %-20s %7.1f%% %7.1f%% %7.1fMB %7.1fMB\n",
            name.c_str(),
            p.avgCpuUsage, p.peakCpuUsage,
            p.avgMemoryMB, p.peakMemoryMB);
    }
}

void SessionReport::printTargetReport(
    const std::vector<SessionTargetSummary>& targets) {
    if (targets.empty()) return;

    printf("\n[ Target Process Summary ]\n");
    for (const auto& t : targets) {
        printf("  +-- %s\n", t.targetName.c_str());
        printf("  |  Path: %s\n", t.exePath.c_str());
        printf("  |  %-14s %7.1f%% (peak %.1f%%)\n",
            "CPU(Total)", t.avgCpuUsage, t.peakCpuUsage);
        printf("  |  %-14s %7.1fMB (peak %.1fMB)\n",
            "Memory", t.avgMemoryMB, t.peakMemoryMB);
        printf("  |  %-14s %7.2fMbps (peak %.2fMbps)\n",
            "Network", t.avgNetMbps, t.peakNetMbps);
        printf("  |  %-14s %7u\n",
            "Peak Threads", t.peakThreadCount);
        printf("  |  %-14s %7u\n",
            "Peak Handles", t.peakHandleCount);
        printf("  |  %-14s %7.0fsec (%.1fmin)\n",
            "Run Time", t.runTime,
            t.runTime / 60.0);
        printf("  +%s\n", std::string(44, '-').c_str());
    }
}

void SessionReport::printAnomalies() {
    dataStore.withConnection([](duckdb::Connection& con) -> void {
        std::string date = DateUtil::today();
        printf("\n[ Anomaly Detection ]\n");

        // CPU 90% 이상 지속
        auto stmt1 = con.Prepare(
            "SELECT procName, COUNT(*) AS cnt "
            "FROM proc_snapshot WHERE procCpuUsage > 90 "
            "   AND CAST(epoch_ms(CAST((CAST(timestamp AS BIGINT) + 32400000000) / 1000 AS BIGINT)) AS DATE) = CAST(? AS DATE) "
            "GROUP BY procName HAVING cnt >= 10 "
            "ORDER BY cnt DESC LIMIT 5");
        if (stmt1->HasError()) {
            spdlog::error("SessionReport: printAnomalies prepare(cpu): {}", stmt1->GetError());
        }
        else {
            auto r1 = stmt1->Execute(duckdb::Value(date));
            if (!r1->HasError()) {
                auto chunk = r1->Fetch();
                bool found = false;
                while (chunk) {
                    for (size_t i = 0; i < chunk->size(); ++i) {
                        printf("  [!] CPU 90%% over: %s (%s sec)\n",
                            chunk->GetValue(0, i).ToString().c_str(),
                            chunk->GetValue(1, i).ToString().c_str());
                        found = true;
                    }
                    chunk = r1->Fetch();
                }
                if (!found) printf("  [OK] CPU fine \n");
            }
        }

        // 메모리 500MB 이상 증가
        auto stmt2 = con.Prepare(
            "SELECT procName, "
            "  ROUND(MIN(procMemoryMB),1) AS s, "
            "  ROUND(MAX(procMemoryMB),1) AS e, "
            "  ROUND(MAX(procMemoryMB)-MIN(procMemoryMB),1) AS g "
            "FROM proc_snapshot "
            "WHERE CAST(epoch_ms(CAST((CAST(timestamp AS BIGINT) + 32400000000) / 1000 AS BIGINT)) AS DATE) = CAST(? AS DATE) "
            "GROUP BY procName HAVING g > 500 "
            "ORDER BY g DESC LIMIT 5");
        if (stmt2->HasError()) {
            spdlog::error("SessionReport: printAnomalies prepare(mem): {}", stmt2->GetError());
        }
        else {
            auto r2 = stmt2->Execute(duckdb::Value(date));
            if (!r2->HasError()) {
                auto chunk = r2->Fetch();
                bool found = false;
                while (chunk) {
                    for (size_t i = 0; i < chunk->size(); ++i) {
                        printf("  [!] Suspected memory leak: %s "
                            "(%.1f -> %.1fMB, +%.1fMB)\n",
                            chunk->GetValue(0, i).ToString().c_str(),
                            safeStod(chunk->GetValue(1, i).ToString()),
                            safeStod(chunk->GetValue(2, i).ToString()),
                            safeStod(chunk->GetValue(3, i).ToString()));
                        found = true;
                    }
                    chunk = r2->Fetch();
                }
                if (!found) printf("  [OK] No memory leaks\n");
            }
        }

        // 타겟 핸들 1000 초과 -> 브라우저는 일반적으로 5000개
        if (con.Query("SELECT * FROM target_snapshot LIMIT 1")
            ->RowCount() > 0) {
            auto stmt3 = con.Prepare(
                "SELECT targetName, MAX(totalHandleCount) AS maxH "
                "FROM target_snapshot "
                "WHERE CAST(epoch_ms(CAST((CAST(timestamp AS BIGINT) + 32400000000) / 1000 AS BIGINT)) AS DATE) = CAST(? AS DATE) "
                "GROUP BY targetName HAVING maxH > 5000 "
                "ORDER BY maxH DESC");
            if (stmt3->HasError()) {
                spdlog::error("SessionReport: printAnomalies prepare(handle): {}", stmt3->GetError());
                return;
            }
            auto r3 = stmt3->Execute(duckdb::Value(date));
            if (!r3->HasError()) {
                auto chunk = r3->Fetch();
                while (chunk) {
                    for (size_t i = 0; i < chunk->size(); ++i)
                        printf("  [!] Suspected handle leak: %s (MAX %s)\n",
                            chunk->GetValue(0, i).ToString().c_str(),
                            chunk->GetValue(1, i).ToString().c_str());
                    chunk = r3->Fetch();
                }
            }
        }
        });
}

