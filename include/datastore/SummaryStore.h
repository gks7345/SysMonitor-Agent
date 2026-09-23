#pragma once
#include <string>
#include <chrono>
#include <spdlog/spdlog.h>
#include <cmath>
#include <filesystem>
#include <nlohmann/json.hpp>
#include "duckdb.hpp"
#include "models/SnapshotData.h"
#include "models/SessionSummary.h"
#include "util/DateUtil.h"


// -------------------------------------------------------
// SummaryStore
// ��¥�� ���� ��� ���� + ���� ���� ��ȸ
// SessionReport ����� �޾� DB ����
// TargetCollector�� ������ ���� ����
// -------------------------------------------------------
class SummaryStore {
private:
    duckdb::DuckDB     db;
    duckdb::Connection con;
    std::mutex mtx;

    void initDB();
    static double safeStod(const std::string& s);
    static int safeStoi(const std::string& s);
    static uint32_t safeStoul(const std::string& s);
    static std::string ensurePath(const std::string& path);
    static SessionTargetSummary parseTargetRow(duckdb::DataChunk* chunk, size_t row);

public:
    SummaryStore();
    ~SummaryStore() = default;

    // SessionReport ��� ���� (���� ���� �� ȣ��)
    void flushSysSummary(const SessionSysSummary& s);
    void flushProcSummaries(const std::vector<SessionProcSummary>& procs);
    void flushTargetSummaries(const std::vector<SessionTargetSummary>& targets);

    // ������ ���� ��ȸ (TargetCollector�� ����)
    SessionTargetSummary getTargetLastSession(const std::string& name);

    // ���� ������ ��ȯ
    std::string getTargetSummariesByDate(const std::string& date);
    std::string getSysSummaryByDate(const std::string& date);
    std::string getProcSummariesByDate(const std::string& date);
    std::string getAvailableDates();

    void flushSummary();
    std::string queryReport(const std::string& sql);
};