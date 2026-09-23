#pragma once
#include <iostream>
#include <algorithm>
#include <thread>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include "datastore/DataStore.h"
#include "datastore/SummaryStore.h"
#include "analysis/SessionReport.h"
#include "collectors/ProcessCollector.h" // SortCriterion enum (process/top 정렬 기준)
#include "collectors/TargetCollector.h"	// 타겟 등록/해제

class ApiServer {
private:
	httplib::Server server;
	DataStore& dataStore;
	SummaryStore& summaryStore;
	SessionReport& sessionReport;
	TargetCollector& targetCollector;
	std::thread serverThread;

	void registerRoutes();

	static void setNoCache(httplib::Response& res);
	static void setCors(httplib::Response& res);
	static void setJsonResponse(httplib::Response& res, const nlohmann::json& j);

	bool validateHour(const httplib::Request& req, httplib::Response& res, int& outHour); // hour(0~23) 필수
	bool validateName(const httplib::Request& req, httplib::Response& res, std::string& outName); // name 필수
	bool validateDate(const httplib::Request& req, httplib::Response& res, std::string& outDate); // date 필수

	static nlohmann::json targetToJson(const SnapshotTarget& t); // SnapshotTarget -> json
	nlohmann::json recentTargetToJson(const std::string& filterName, size_t n); // Recent Targets -> json
public:
	ApiServer(DataStore& dataStore, SummaryStore& summaryStore, SessionReport& sessionReport, TargetCollector& targetCollector);
	void start(int port = 8080);
	void stop();
};