#include "datastore/GapBuffer.h"

#include <filesystem>

#include <spdlog/spdlog.h>
#include "duckdb.hpp"

namespace {
    // 쿼리 하나를 실행하고 실패하면 로그를 남긴다. 성공 여부를 돌려준다.
    bool run(duckdb::Connection& con, const std::string& sql, const char* what) {
        auto result = con.Query(sql);
        if (result->HasError()) {
            spdlog::error("[GapBuffer] {} failed: {}", what, result->GetError());
            return false;
        }
        return true;
    }

    // DELETE / UPDATE 결과의 영향받은 행 수 (DuckDB는 첫 열 첫 행에 돌려준다)
    size_t affectedRows(duckdb::QueryResult& result) {
        auto chunk = result.Fetch();
        if (!chunk || chunk->size() == 0) {
            return 0;
        }
        return static_cast<size_t>(chunk->GetValue(0, 0).GetValue<int64_t>());
    }
}

GapBuffer::GapBuffer(const std::string& path, int retentionHours)
    : retentionUs_(static_cast<int64_t>(retentionHours) * 3600LL * 1000 * 1000) {
    try {
        const std::filesystem::path parent = std::filesystem::path(path).parent_path();
        if (!parent.empty()) {
            std::filesystem::create_directories(parent);
        }
        db_ = std::make_unique<duckdb::DuckDB>(path);
        con_ = std::make_unique<duckdb::Connection>(*db_);
    }
    catch (const std::exception& e) {
        spdlog::error("[GapBuffer] could not open {} ({}) — snapshots taken while disconnected will be lost", path, e.what());
        con_.reset();
        db_.reset();
        return;
    }

    if (!run(*con_, R"(
            CREATE TABLE IF NOT EXISTS gap_buffer (
                id               BIGINT PRIMARY KEY,
                timestamp_us     BIGINT NOT NULL,
                instance_id      VARCHAR NOT NULL,
                protocol_version INTEGER NOT NULL,
                sent_realtime    BOOLEAN NOT NULL,
                payload          BLOB NOT NULL
            ))", "create table")) {
        con_.reset();
        db_.reset();
        return;
    }

    // 순번은 이전 실행에서 남은 행 뒤로 이어 붙인다 — 남은 행은 다음 연결 때 함께 보낸다.
    auto result = con_->Query("SELECT COALESCE(MAX(id), 0) FROM gap_buffer");
    if (!result->HasError()) {
        auto chunk = result->Fetch();
        if (chunk && chunk->size() > 0) {
            nextId_ = chunk->GetValue(0, 0).GetValue<int64_t>() + 1;
        }
    }
    const size_t left = count();
    spdlog::info("[GapBuffer] {} opened ({} snapshot(s) left from before, kept for {}h)", path, left, retentionHours);
}

GapBuffer::~GapBuffer() = default;

void GapBuffer::append(const std::vector<BufferedSnapshot>& rows) {
    if (rows.empty()) {
        return;
    }
    if (!con_) {
        if (!dropWarned_) {
            dropWarned_ = true;
            spdlog::error("[GapBuffer] buffer is not open — dropping snapshots taken while disconnected");
        }
        return;
    }
    try {
        duckdb::Appender appender(*con_, "gap_buffer");
        for (const auto& row : rows) {
            appender.BeginRow();
            appender.Append<int64_t>(nextId_++);
            appender.Append<int64_t>(row.timestampUs);
            appender.Append(duckdb::Value(row.instanceId));
            appender.Append<int32_t>(static_cast<int32_t>(row.protocolVersion));
            appender.Append<bool>(row.sentRealtime);
            appender.Append(duckdb::Value::BLOB(reinterpret_cast<duckdb::const_data_ptr_t>(row.payload.data()), row.payload.size()));
            appender.EndRow();
        }
        appender.Close();
    }
    catch (const std::exception& e) {
        spdlog::error("[GapBuffer] append of {} snapshot(s) failed: {}", rows.size(), e.what());
    }
}

GapBuffer::ReconcileResult GapBuffer::reconcile(std::optional<int64_t> serverLastUs, uint32_t currentProtocolVersion) {
    ReconcileResult r;
    if (!con_) {
        return r;
    }

    auto versionStmt = con_->Prepare("DELETE FROM gap_buffer WHERE protocol_version <> ?");
    auto versionResult = versionStmt->Execute(static_cast<int32_t>(currentProtocolVersion));
    if (versionResult->HasError()) {
        spdlog::error("[GapBuffer] dropping other-version rows failed: {}", versionResult->GetError());
    } else {
        r.versionDropped = affectedRows(*versionResult);
    }

    if (serverLastUs) {
        // 시각의 크기가 아니라 보낸 순서로 판정한다: 서버는 한 스트림을 쓴 순서대로 읽으므로, 서버가 마지막으로 읽은 틱보다
        // 먼저 쓴 행은 받은 것이다. 그 틱을 찾지 못하면(다른 PC가 남긴 R, 이미 정리된 틱) 아무것도 지우지 않는다 — 다시 보내 중복이 될 뿐이다.
        // 같은 시각이 여러 번 있으면 가장 앞의 것을 기준으로 삼아, 틀려도 덜 지우는 쪽으로만 틀린다.
        auto stmt = con_->Prepare("DELETE FROM gap_buffer WHERE sent_realtime AND id < "
                                  "(SELECT MIN(id) FROM gap_buffer WHERE sent_realtime AND timestamp_us = ?)");
        auto result = stmt->Execute(*serverLastUs);
        if (result->HasError()) {
            spdlog::error("[GapBuffer] dropping confirmed rows failed: {}", result->GetError());
        } else {
            r.confirmedDropped = affectedRows(*result);
        }
    }
    run(*con_, "UPDATE gap_buffer SET sent_realtime = false WHERE sent_realtime", "clear sent_realtime");

    r.remaining = count();
    return r;
}

std::vector<BufferedSnapshot> GapBuffer::readAfter(int64_t afterId, size_t limit) {
    std::vector<BufferedSnapshot> rows;
    if (!con_) {
        return rows;
    }
    auto stmt = con_->Prepare("SELECT id, timestamp_us, instance_id, protocol_version, sent_realtime, payload "
                              "FROM gap_buffer WHERE id > ? ORDER BY id LIMIT ?");
    auto result = stmt->Execute(afterId, static_cast<int64_t>(limit));
    if (result->HasError()) {
        spdlog::error("[GapBuffer] read failed: {}", result->GetError());
        return rows;
    }
    for (auto chunk = result->Fetch(); chunk && chunk->size() > 0; chunk = result->Fetch()) {
        for (duckdb::idx_t i = 0; i < chunk->size(); ++i) {
            BufferedSnapshot row;
            row.id = chunk->GetValue(0, i).GetValue<int64_t>();
            row.timestampUs = chunk->GetValue(1, i).GetValue<int64_t>();
            row.instanceId = chunk->GetValue(2, i).GetValue<std::string>();
            row.protocolVersion = static_cast<uint32_t>(chunk->GetValue(3, i).GetValue<int32_t>());
            row.sentRealtime = chunk->GetValue(4, i).GetValue<bool>();
            row.payload = duckdb::StringValue::Get(chunk->GetValue(5, i));
            rows.push_back(std::move(row));
        }
    }
    return rows;
}

void GapBuffer::removeUpTo(int64_t lastId) {
    if (!con_) {
        return;
    }
    auto stmt = con_->Prepare("DELETE FROM gap_buffer WHERE id <= ?");
    auto result = stmt->Execute(lastId);
    if (result->HasError()) {
        spdlog::error("[GapBuffer] removing sent rows failed: {}", result->GetError());
    }
}

size_t GapBuffer::dropExpired(int64_t nowUs) {
    if (!con_) {
        return 0;
    }
    auto stmt = con_->Prepare("DELETE FROM gap_buffer WHERE timestamp_us < ?");
    auto result = stmt->Execute(nowUs - retentionUs_);
    if (result->HasError()) {
        spdlog::error("[GapBuffer] dropping expired rows failed: {}", result->GetError());
        return 0;
    }
    return affectedRows(*result);
}

size_t GapBuffer::count() {
    if (!con_) {
        return 0;
    }
    auto result = con_->Query("SELECT COUNT(*) FROM gap_buffer");
    if (result->HasError()) {
        spdlog::error("[GapBuffer] count failed: {}", result->GetError());
        return 0;
    }
    auto chunk = result->Fetch();
    return (chunk && chunk->size() > 0) ? static_cast<size_t>(chunk->GetValue(0, 0).GetValue<int64_t>()) : 0;
}
