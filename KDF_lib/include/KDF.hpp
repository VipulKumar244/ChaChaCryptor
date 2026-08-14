#pragma once

#include <Chacha_Stream.hpp>

#include <string_view>

namespace pfe {

key derive_key(std::string_view password, std::string_view salt,
               unsigned int iterations = 100'000);

} 
