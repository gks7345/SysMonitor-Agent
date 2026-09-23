#pragma once
#include <string>
#include <vector>
#include "duckdb.hpp"
#include "models/SnapshotData.h"
#include "models/SessionSummary.h"
#include "datastore/SummaryStore.h"
#include "datastore/DataStore.h"
#include "util/DateUtil.h"
#include <spdlog/spdlog.h>


class SessionReport {
private:
	DataStore& dataStore;

	void printSysReport(const SessionSysSummary& s);
	void printProcReport(const std::vector<SessionProcSummary>& procs);
	void printTargetReport(const std::vector<SessionTargetSummary>& targets);
	void printAnomalies();

	static double safeStod(const std::string& s);
	static int safeStoi(const std::string& s);
public:
	explicit SessionReport(DataStore& dataStore);

	// 분석
	SessionSysSummary analyzeSys();
	std::vector<SessionProcSummary>   analyzeProcs(int topN = 10);
	std::vector<SessionTargetSummary> analyzeTargets();
	SessionTargetSummary getSessionTargetSummaryOne(const std::string& name);

	// 분석 결과 출력
	void printReport();
};