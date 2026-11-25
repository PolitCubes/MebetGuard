// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
// Minimal streaming JSON writer for report events (Sentry/GlitchTip format, ТЗ §12).
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace mebet {

class JsonWriter {
public:
    JsonWriter& begin_object();
    JsonWriter& end_object();
    JsonWriter& begin_array();
    JsonWriter& end_array();
    JsonWriter& key(std::string_view k);
    JsonWriter& value(std::string_view v);
    JsonWriter& value(const char* v) { return value(std::string_view(v ? v : "")); }
    JsonWriter& value(std::int64_t v);
    JsonWriter& value(std::uint64_t v);
    JsonWriter& value(int v) { return value(static_cast<std::int64_t>(v)); }
    JsonWriter& value(unsigned v) { return value(static_cast<std::uint64_t>(v)); }
    JsonWriter& value(bool v);
    JsonWriter& value_double(double v);
    JsonWriter& null_value();
    // Inserts an already serialized JSON value.
    JsonWriter& raw(std::string_view json);

    // key + value in one call.
    template <typename T>
    JsonWriter& field(std::string_view k, const T& v) {
        key(k);
        return value(v);
    }

    const std::string& str() const { return out_; }
    std::string take() { return std::move(out_); }

private:
    void comma();
    void escape(std::string_view s);

    std::string out_;
    std::vector<bool> first_;  // one entry per open container
    bool after_key_ = false;
};

}  // namespace mebet
