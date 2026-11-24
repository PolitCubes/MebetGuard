#include "json_writer.hpp"

#include <cstdio>

#include "strings.hpp"

namespace mebet {

void JsonWriter::comma() {
    if (after_key_) {
        after_key_ = false;
        return;
    }
    if (!first_.empty()) {
        if (!first_.back()) out_.push_back(',');
        first_.back() = false;
    }
}

void JsonWriter::escape(std::string_view s) {
    const std::string clean = sanitize_utf8(s);
    out_.push_back('"');
    for (unsigned char c : clean) {
        switch (c) {
            case '"': out_ += "\\\""; break;
            case '\\': out_ += "\\\\"; break;
            case '\n': out_ += "\\n"; break;
            case '\r': out_ += "\\r"; break;
            case '\t': out_ += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out_ += buf;
                } else {
                    out_.push_back(static_cast<char>(c));
                }
        }
    }
    out_.push_back('"');
}

JsonWriter& JsonWriter::begin_object() {
    comma();
    out_.push_back('{');
    first_.push_back(true);
    return *this;
}

JsonWriter& JsonWriter::end_object() {
    out_.push_back('}');
    if (!first_.empty()) first_.pop_back();
    return *this;
}

JsonWriter& JsonWriter::begin_array() {
    comma();
    out_.push_back('[');
    first_.push_back(true);
    return *this;
}

JsonWriter& JsonWriter::end_array() {
    out_.push_back(']');
    if (!first_.empty()) first_.pop_back();
    return *this;
}

JsonWriter& JsonWriter::key(std::string_view k) {
    comma();
    escape(k);
    out_.push_back(':');
    after_key_ = true;
    return *this;
}

JsonWriter& JsonWriter::value(std::string_view v) {
    comma();
    escape(v);
    return *this;
}

JsonWriter& JsonWriter::value(std::int64_t v) {
    comma();
    out_ += std::to_string(v);
    return *this;
}

JsonWriter& JsonWriter::value(std::uint64_t v) {
    comma();
    out_ += std::to_string(v);
    return *this;
}

JsonWriter& JsonWriter::value(bool v) {
    comma();
    out_ += v ? "true" : "false";
    return *this;
}

JsonWriter& JsonWriter::value_double(double v) {
    comma();
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.3f", v);
    out_ += buf;
    return *this;
}

JsonWriter& JsonWriter::null_value() {
    comma();
    out_ += "null";
    return *this;
}

JsonWriter& JsonWriter::raw(std::string_view json) {
    comma();
    out_.append(json.data(), json.size());
    return *this;
}

}  // namespace mebet
