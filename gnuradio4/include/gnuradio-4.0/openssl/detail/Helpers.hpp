// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef GNURADIO4_OPENSSL_DETAIL_HELPERS_HPP
#define GNURADIO4_OPENSSL_DETAIL_HELPERS_HPP

#include <gnuradio-4.0/Tag.hpp>
#include <gnuradio-4.0/Tensor.hpp>
#include <gnuradio-4.0/Value.hpp>

#include <cstddef>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace gnuradio4::openssl::detail {

[[nodiscard]] inline const gr::Tensor<std::uint8_t>* tensorBytesFromMap(const gr::property_map& map, std::string_view keyView) {
    const std::pmr::string key(keyView.begin(), keyView.end());
    const auto              it = map.find(key);
    if (it == map.end()) {
        return nullptr;
    }
    return it->second.get_if<gr::Tensor<std::uint8_t>>();
}

[[nodiscard]] inline std::optional<gr::Size_t> readPduLength(const gr::property_map& map, std::string_view keyView) {
    const std::pmr::string key(keyView.begin(), keyView.end());
    const auto              it = map.find(key);
    if (it == map.end()) {
        return std::nullopt;
    }
    const gr::pmt::Value& v = it->second;
    if (const auto* p = v.get_if<std::uint64_t>()) {
        return static_cast<gr::Size_t>(*p);
    }
    if (const auto* p = v.get_if<std::int64_t>()) {
        return static_cast<gr::Size_t>(*p);
    }
    if (const auto* p = v.get_if<std::uint32_t>()) {
        return static_cast<gr::Size_t>(*p);
    }
    if (const auto* p = v.get_if<std::int32_t>()) {
        return static_cast<gr::Size_t>(*p);
    }
    return std::nullopt;
}

[[nodiscard]] inline bool mapHas(const gr::property_map& map, std::string_view keyView) {
    const std::pmr::string key(keyView.begin(), keyView.end(), map.get_allocator());
    return map.contains(key);
}

inline void eraseKey(gr::property_map& map, std::string_view keyView) {
    const std::pmr::string key(keyView.begin(), keyView.end(), map.get_allocator());
    map.erase(key);
}

inline void overwriteMap(gr::property_map& dst, const gr::property_map& src) {
    dst.clear();
    for (const auto& [k, v] : src) {
        dst.emplace(k, v);
    }
}

[[nodiscard]] inline gr::property_map shallowCopyExcept(const gr::property_map& src, std::string_view omitKeyView) {
    const std::pmr::string omit(omitKeyView.begin(), omitKeyView.end(), src.get_allocator());
    gr::property_map         out(src.get_allocator());
    for (const auto& [k, v] : src) {
        if (k != omit) {
            out.emplace(k, v);
        }
    }
    return out;
}

} // namespace gnuradio4::openssl::detail

#endif
