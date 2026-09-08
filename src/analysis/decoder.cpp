#include "reb/decoder.hpp"

#include <zlib.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <charconv>
#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace reb {
namespace {

constexpr std::string_view kBase64Alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
constexpr std::string_view kBase64UrlAlphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

DecoderResult Failure(DecoderStatus status, std::string message) {
  return {.status = status, .output = {}, .error = std::move(message)};
}

DecoderResult Success(std::vector<std::uint8_t> output) {
  return {.status = DecoderStatus::kOk, .output = std::move(output), .error = {}};
}

bool IsValidUtf8(std::span<const std::uint8_t> input) noexcept {
  std::size_t index = 0;
  while (index < input.size()) {
    const std::uint8_t first = input[index];
    if (first <= 0x7fU) {
      ++index;
      continue;
    }
    std::size_t continuation_count = 0;
    std::uint32_t code_point = 0;
    if ((first & 0xe0U) == 0xc0U) {
      continuation_count = 1;
      code_point = first & 0x1fU;
    } else if ((first & 0xf0U) == 0xe0U) {
      continuation_count = 2;
      code_point = first & 0x0fU;
    } else if ((first & 0xf8U) == 0xf0U) {
      continuation_count = 3;
      code_point = first & 0x07U;
    } else {
      return false;
    }
    if (index + continuation_count >= input.size()) {
      return false;
    }
    for (std::size_t offset = 1; offset <= continuation_count; ++offset) {
      const std::uint8_t continuation = input[index + offset];
      if ((continuation & 0xc0U) != 0x80U) {
        return false;
      }
      code_point = (code_point << 6U) | (continuation & 0x3fU);
    }
    const bool overlong = (continuation_count == 1 && code_point < 0x80U) ||
                          (continuation_count == 2 && code_point < 0x800U) ||
                          (continuation_count == 3 && code_point < 0x10000U);
    if (overlong || code_point > 0x10ffffU || (code_point >= 0xd800U && code_point <= 0xdfffU)) {
      return false;
    }
    index += continuation_count + 1;
  }
  return true;
}

std::vector<std::uint8_t> Base64Encode(std::span<const std::uint8_t> input,
                                       bool url_safe,
                                       bool include_padding) {
  const std::string_view alphabet = url_safe ? kBase64UrlAlphabet : kBase64Alphabet;
  std::vector<std::uint8_t> output;
  output.reserve(((input.size() + 2) / 3) * 4);
  for (std::size_t index = 0; index < input.size(); index += 3) {
    const std::uint32_t first = input[index];
    const std::uint32_t second = index + 1 < input.size() ? input[index + 1] : 0;
    const std::uint32_t third = index + 2 < input.size() ? input[index + 2] : 0;
    const std::uint32_t value = (first << 16U) | (second << 8U) | third;
    output.push_back(static_cast<std::uint8_t>(alphabet[(value >> 18U) & 0x3fU]));
    output.push_back(static_cast<std::uint8_t>(alphabet[(value >> 12U) & 0x3fU]));
    if (index + 1 < input.size()) {
      output.push_back(static_cast<std::uint8_t>(alphabet[(value >> 6U) & 0x3fU]));
    } else if (include_padding) {
      output.push_back(static_cast<std::uint8_t>('='));
    }
    if (index + 2 < input.size()) {
      output.push_back(static_cast<std::uint8_t>(alphabet[value & 0x3fU]));
    } else if (include_padding) {
      output.push_back(static_cast<std::uint8_t>('='));
    }
  }
  return output;
}

int Base64Value(const std::uint8_t byte, const bool url_safe) noexcept {
  if (byte >= 'A' && byte <= 'Z') {
    return byte - 'A';
  }
  if (byte >= 'a' && byte <= 'z') {
    return byte - 'a' + 26;
  }
  if (byte >= '0' && byte <= '9') {
    return byte - '0' + 52;
  }
  if ((!url_safe && byte == '+') || (url_safe && byte == '-')) {
    return 62;
  }
  if ((!url_safe && byte == '/') || (url_safe && byte == '_')) {
    return 63;
  }
  return -1;
}

DecoderResult Base64Decode(std::span<const std::uint8_t> input,
                           const bool url_safe,
                           const std::size_t output_limit) {
  if (input.empty()) {
    return Success({});
  }
  std::size_t meaningful_size = input.size();
  std::size_t padding = 0;
  while (meaningful_size > 0 && input[meaningful_size - 1] == '=') {
    --meaningful_size;
    ++padding;
  }
  if (padding > 2 || (!url_safe && input.size() % 4 != 0) || meaningful_size % 4 == 1) {
    return Failure(DecoderStatus::kInvalidInput, "Base64 padding is invalid");
  }
  if (url_safe && padding != 0 && input.size() % 4 != 0) {
    return Failure(DecoderStatus::kInvalidInput, "Base64URL padding is invalid");
  }
  const std::size_t decoded_size = (meaningful_size * 6) / 8;
  if (decoded_size > output_limit) {
    return Failure(DecoderStatus::kOutputLimit, "Decoded output exceeds the configured byte limit");
  }
  std::vector<std::uint8_t> output;
  output.reserve(decoded_size);
  std::uint32_t accumulator = 0;
  unsigned int bit_count = 0;
  for (std::size_t index = 0; index < meaningful_size; ++index) {
    const int value = Base64Value(input[index], url_safe);
    if (value < 0) {
      return Failure(DecoderStatus::kInvalidInput,
                     url_safe ? "Base64URL input contains an invalid character"
                              : "Base64 input contains an invalid character");
    }
    accumulator = (accumulator << 6U) | static_cast<std::uint32_t>(value);
    bit_count += 6;
    if (bit_count >= 8) {
      bit_count -= 8;
      output.push_back(static_cast<std::uint8_t>(accumulator >> bit_count));
      if (bit_count == 0) {
        accumulator = 0;
      } else {
        accumulator &= (1U << bit_count) - 1U;
      }
    }
  }
  if (accumulator != 0) {
    return Failure(DecoderStatus::kInvalidInput, "Base64 trailing bits are not canonical");
  }
  return Success(std::move(output));
}

int HexValue(const std::uint8_t byte) noexcept {
  if (byte >= '0' && byte <= '9') {
    return byte - '0';
  }
  if (byte >= 'a' && byte <= 'f') {
    return byte - 'a' + 10;
  }
  if (byte >= 'A' && byte <= 'F') {
    return byte - 'A' + 10;
  }
  return -1;
}

DecoderResult HexDecode(std::span<const std::uint8_t> input, const std::size_t output_limit) {
  std::vector<std::uint8_t> digits;
  digits.reserve(input.size());
  for (std::size_t index = 0; index < input.size(); ++index) {
    const std::uint8_t byte = input[index];
    if (std::isspace(static_cast<unsigned char>(byte)) != 0 || byte == ':' || byte == '-') {
      continue;
    }
    if (byte == '0' && index + 1 < input.size() &&
        (input[index + 1] == 'x' || input[index + 1] == 'X')) {
      ++index;
      continue;
    }
    if (HexValue(byte) < 0) {
      return Failure(DecoderStatus::kInvalidInput, "Hex input contains an invalid character");
    }
    digits.push_back(byte);
  }
  if (digits.size() % 2 != 0) {
    return Failure(DecoderStatus::kInvalidInput, "Hex input must contain complete byte pairs");
  }
  if (digits.size() / 2 > output_limit) {
    return Failure(DecoderStatus::kOutputLimit, "Decoded output exceeds the configured byte limit");
  }
  std::vector<std::uint8_t> output;
  output.reserve(digits.size() / 2);
  for (std::size_t index = 0; index < digits.size(); index += 2) {
    output.push_back(
        static_cast<std::uint8_t>((HexValue(digits[index]) << 4) | HexValue(digits[index + 1])));
  }
  return Success(std::move(output));
}

bool IsUrlUnreserved(const std::uint8_t byte) noexcept {
  return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
         (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' || byte == '_' || byte == '~';
}

DecoderResult UrlEncode(std::span<const std::uint8_t> input, const std::size_t output_limit) {
  constexpr char kHex[] = "0123456789ABCDEF";
  std::size_t encoded_size = 0;
  for (const std::uint8_t byte : input) {
    encoded_size += IsUrlUnreserved(byte) ? std::size_t{1} : std::size_t{3};
    if (encoded_size > output_limit) {
      return Failure(DecoderStatus::kOutputLimit,
                     "Encoded output exceeds the configured byte limit");
    }
  }
  std::vector<std::uint8_t> output;
  output.reserve(encoded_size);
  for (const std::uint8_t byte : input) {
    if (IsUrlUnreserved(byte)) {
      output.push_back(byte);
      continue;
    }
    output.push_back('%');
    output.push_back(static_cast<std::uint8_t>(kHex[byte >> 4U]));
    output.push_back(static_cast<std::uint8_t>(kHex[byte & 0x0fU]));
  }
  return Success(std::move(output));
}

DecoderResult UrlDecode(std::span<const std::uint8_t> input, const std::size_t output_limit) {
  if (input.size() > output_limit) {
    return Failure(DecoderStatus::kOutputLimit, "Decoded output exceeds the configured byte limit");
  }
  std::vector<std::uint8_t> output;
  output.reserve(input.size());
  for (std::size_t index = 0; index < input.size(); ++index) {
    if (input[index] != '%') {
      output.push_back(input[index]);
      continue;
    }
    if (index + 2 >= input.size()) {
      return Failure(DecoderStatus::kInvalidInput, "URL input ends inside a percent escape");
    }
    const int high = HexValue(input[index + 1]);
    const int low = HexValue(input[index + 2]);
    if (high < 0 || low < 0) {
      return Failure(DecoderStatus::kInvalidInput, "URL input contains an invalid percent escape");
    }
    output.push_back(static_cast<std::uint8_t>((high << 4) | low));
    index += 2;
  }
  return Success(std::move(output));
}

DecoderResult DecimalToBase36(std::span<const std::uint8_t> input, const std::size_t output_limit) {
  if (input.empty() || !IsValidUtf8(input)) {
    return Failure(DecoderStatus::kInvalidInput, "Base36 encoding requires a decimal integer");
  }
  std::size_t start = 0;
  bool negative = false;
  if (input[0] == '-' || input[0] == '+') {
    negative = input[0] == '-';
    start = 1;
  }
  if (start == input.size()) {
    return Failure(DecoderStatus::kInvalidInput, "Base36 encoding requires a decimal integer");
  }
  while (start + 1 < input.size() && input[start] == '0') {
    ++start;
  }
  std::vector<std::uint8_t> decimal;
  decimal.reserve(input.size() - start);
  for (std::size_t index = start; index < input.size(); ++index) {
    if (input[index] < '0' || input[index] > '9') {
      return Failure(DecoderStatus::kInvalidInput, "Base36 encoding requires a decimal integer");
    }
    decimal.push_back(static_cast<std::uint8_t>(input[index] - '0'));
  }
  if (std::all_of(decimal.begin(), decimal.end(),
                  [](const std::uint8_t value) { return value == 0; })) {
    return Success({'0'});
  }
  constexpr char kDigits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
  std::vector<std::uint8_t> reversed;
  while (!decimal.empty()) {
    unsigned int remainder = 0;
    std::size_t first_nonzero = decimal.size();
    for (std::size_t index = 0; index < decimal.size(); ++index) {
      const unsigned int value = remainder * 10U + decimal[index];
      decimal[index] = static_cast<std::uint8_t>(value / 36U);
      remainder = value % 36U;
      if (first_nonzero == decimal.size() && decimal[index] != 0) {
        first_nonzero = index;
      }
    }
    reversed.push_back(static_cast<std::uint8_t>(kDigits[remainder]));
    if (reversed.size() + static_cast<std::size_t>(negative) > output_limit) {
      return Failure(DecoderStatus::kOutputLimit,
                     "Base36 output exceeds the configured byte limit");
    }
    if (first_nonzero == decimal.size()) {
      decimal.clear();
    } else if (first_nonzero > 0) {
      decimal.erase(decimal.begin(), decimal.begin() + static_cast<std::ptrdiff_t>(first_nonzero));
    }
  }
  std::vector<std::uint8_t> output;
  output.reserve(reversed.size() + static_cast<std::size_t>(negative));
  if (negative) {
    output.push_back('-');
  }
  output.insert(output.end(), reversed.rbegin(), reversed.rend());
  return Success(std::move(output));
}

DecoderResult Base36ToDecimal(std::span<const std::uint8_t> input, const std::size_t output_limit) {
  if (input.empty() || !IsValidUtf8(input)) {
    return Failure(DecoderStatus::kInvalidInput, "Base36 decoding requires an integer");
  }
  std::size_t start = 0;
  bool negative = false;
  if (input[0] == '-' || input[0] == '+') {
    negative = input[0] == '-';
    start = 1;
  }
  if (start == input.size()) {
    return Failure(DecoderStatus::kInvalidInput, "Base36 decoding requires an integer");
  }
  std::vector<std::uint8_t> decimal = {0};
  for (std::size_t index = start; index < input.size(); ++index) {
    const std::uint8_t byte = input[index];
    unsigned int digit = 0;
    if (byte >= '0' && byte <= '9') {
      digit = byte - '0';
    } else if (byte >= 'a' && byte <= 'z') {
      digit = byte - 'a' + 10U;
    } else if (byte >= 'A' && byte <= 'Z') {
      digit = byte - 'A' + 10U;
    } else {
      return Failure(DecoderStatus::kInvalidInput, "Base36 input contains an invalid character");
    }
    unsigned int carry = digit;
    for (auto iterator = decimal.rbegin(); iterator != decimal.rend(); ++iterator) {
      const unsigned int value = static_cast<unsigned int>(*iterator) * 36U + carry;
      *iterator = static_cast<std::uint8_t>(value % 10U);
      carry = value / 10U;
    }
    while (carry > 0) {
      decimal.insert(decimal.begin(), static_cast<std::uint8_t>(carry % 10U));
      carry /= 10U;
    }
    if (decimal.size() + static_cast<std::size_t>(negative) > output_limit) {
      return Failure(DecoderStatus::kOutputLimit,
                     "Decimal output exceeds the configured byte limit");
    }
  }
  const auto first_nonzero = std::find_if(decimal.begin(), decimal.end(),
                                          [](const std::uint8_t digit) { return digit != 0; });
  if (first_nonzero == decimal.end()) {
    return Success({'0'});
  }
  std::vector<std::uint8_t> output;
  output.reserve(static_cast<std::size_t>(decimal.end() - first_nonzero) +
                 static_cast<std::size_t>(negative));
  if (negative) {
    output.push_back('-');
  }
  for (auto iterator = first_nonzero; iterator != decimal.end(); ++iterator) {
    output.push_back(static_cast<std::uint8_t>('0' + *iterator));
  }
  return Success(std::move(output));
}

DecoderResult ZlibTransform(std::span<const std::uint8_t> input,
                            const bool compress,
                            const int window_bits,
                            const std::size_t output_limit) {
  if (input.size() > static_cast<std::size_t>(std::numeric_limits<uInt>::max())) {
    return Failure(DecoderStatus::kInvalidInput, "Compression input is too large");
  }
  z_stream stream{};
  int status =
      compress ? deflateInit2(&stream, Z_BEST_SPEED, Z_DEFLATED, window_bits, 8, Z_DEFAULT_STRATEGY)
               : inflateInit2(&stream, window_bits);
  if (status != Z_OK) {
    return Failure(DecoderStatus::kInternalError, "Compression engine initialization failed");
  }
  stream.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(input.data()));
  stream.avail_in = static_cast<uInt>(input.size());
  std::vector<std::uint8_t> output;
  constexpr std::size_t kChunkBytes = 32U << 10U;
  std::array<std::uint8_t, kChunkBytes> chunk{};
  do {
    stream.next_out = chunk.data();
    stream.avail_out = static_cast<uInt>(chunk.size());
    status = compress ? deflate(&stream, Z_FINISH) : inflate(&stream, Z_NO_FLUSH);
    if (status != Z_OK && status != Z_STREAM_END && !(compress && status == Z_BUF_ERROR)) {
      if (compress) {
        deflateEnd(&stream);
      } else {
        inflateEnd(&stream);
      }
      return Failure(
          DecoderStatus::kInvalidInput,
          compress ? "Compression failed" : "Compressed input is malformed or truncated");
    }
    const std::size_t produced = chunk.size() - stream.avail_out;
    if (produced > output_limit - std::min(output.size(), output_limit)) {
      if (compress) {
        deflateEnd(&stream);
      } else {
        inflateEnd(&stream);
      }
      return Failure(DecoderStatus::kOutputLimit,
                     "Compression output exceeds the configured byte limit");
    }
    output.insert(output.end(), chunk.begin(),
                  chunk.begin() + static_cast<std::ptrdiff_t>(produced));
    if (!compress && status == Z_STREAM_END && stream.avail_in != 0) {
      if (window_bits != MAX_WBITS + 16) {
        inflateEnd(&stream);
        return Failure(DecoderStatus::kInvalidInput, "Compressed input contains trailing data");
      }
      // Gzip permits concatenated members. Reuse the inflater's allocation,
      // retaining unread input and the aggregate output budget across members.
      status = inflateReset(&stream);
      if (status != Z_OK) {
        inflateEnd(&stream);
        return Failure(DecoderStatus::kInternalError,
                       "Compression engine could not reset for the next gzip member");
      }
    }
    if (status == Z_BUF_ERROR && produced == 0) {
      break;
    }
  } while (status != Z_STREAM_END);
  if (compress) {
    deflateEnd(&stream);
  } else {
    inflateEnd(&stream);
  }
  if (status != Z_STREAM_END) {
    return Failure(DecoderStatus::kInvalidInput,
                   compress ? "Compression did not finish" : "Compressed input is truncated");
  }
  return Success(std::move(output));
}

class JsonFormatter final {
 public:
  JsonFormatter(std::string_view input, const bool pretty, const std::size_t output_limit)
      : input_(input), pretty_(pretty), output_limit_(output_limit) {}

  DecoderResult Run() {
    const auto bytes = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(input_.data()), input_.size());
    if (!IsValidUtf8(bytes)) {
      return Failure(DecoderStatus::kInvalidInput, "JSON input is not valid UTF-8");
    }
    SkipWhitespace();
    if (!ParseValue(0)) {
      return Failure(limit_reached_ ? DecoderStatus::kOutputLimit : DecoderStatus::kInvalidInput,
                     error_.empty() ? "JSON input is malformed" : error_);
    }
    SkipWhitespace();
    if (position_ != input_.size()) {
      return Failure(DecoderStatus::kInvalidInput, "JSON input has trailing content");
    }
    return Success(std::vector<std::uint8_t>(output_.begin(), output_.end()));
  }

 private:
  bool Append(const char character) {
    if (output_.size() >= output_limit_) {
      limit_reached_ = true;
      error_ = "JSON output exceeds the configured byte limit";
      return false;
    }
    output_.push_back(character);
    return true;
  }

  bool Append(const std::string_view text) {
    if (text.size() > output_limit_ - std::min(output_.size(), output_limit_)) {
      limit_reached_ = true;
      error_ = "JSON output exceeds the configured byte limit";
      return false;
    }
    output_.append(text);
    return true;
  }

  bool NewlineAndIndent(const std::size_t depth) {
    if (!pretty_) {
      return true;
    }
    if (!Append('\n')) {
      return false;
    }
    if (depth > (output_limit_ - std::min(output_.size(), output_limit_)) / 2) {
      limit_reached_ = true;
      error_ = "JSON output exceeds the configured byte limit";
      return false;
    }
    return Append(std::string(depth * 2, ' '));
  }

  void SkipWhitespace() noexcept {
    while (position_ < input_.size() && (input_[position_] == ' ' || input_[position_] == '\n' ||
                                         input_[position_] == '\r' || input_[position_] == '\t')) {
      ++position_;
    }
  }

  bool Token() {
    ++tokens_;
    if (tokens_ > kDecoderMaxJsonTokens) {
      error_ = "JSON token count exceeds the configured limit";
      return false;
    }
    return true;
  }

  bool ParseValue(const std::size_t depth) {
    if (depth > kDecoderMaxJsonDepth) {
      error_ = "JSON nesting exceeds the configured depth limit";
      return false;
    }
    SkipWhitespace();
    if (position_ >= input_.size() || !Token()) {
      return false;
    }
    switch (input_[position_]) {
      case '{':
        return ParseObject(depth);
      case '[':
        return ParseArray(depth);
      case '"':
        return ParseString();
      case 't':
        return ParseLiteral("true");
      case 'f':
        return ParseLiteral("false");
      case 'n':
        return ParseLiteral("null");
      default:
        return ParseNumber();
    }
  }

  bool ParseObject(const std::size_t depth) {
    ++position_;
    if (!Append('{')) {
      return false;
    }
    SkipWhitespace();
    if (position_ < input_.size() && input_[position_] == '}') {
      ++position_;
      return Append('}');
    }
    std::size_t entry_count = 0;
    while (position_ < input_.size()) {
      if (entry_count > 0 && !Append(',')) {
        return false;
      }
      if (!NewlineAndIndent(depth + 1)) {
        return false;
      }
      SkipWhitespace();
      if (position_ >= input_.size() || input_[position_] != '"' || !Token() || !ParseString()) {
        if (error_.empty()) {
          error_ = "JSON object keys must be strings";
        }
        return false;
      }
      SkipWhitespace();
      if (position_ >= input_.size() || input_[position_] != ':') {
        error_ = "JSON object key is missing a colon";
        return false;
      }
      ++position_;
      if (!Append(pretty_ ? ": " : ":")) {
        return false;
      }
      if (!ParseValue(depth + 1)) {
        return false;
      }
      ++entry_count;
      SkipWhitespace();
      if (position_ < input_.size() && input_[position_] == '}') {
        ++position_;
        if (!NewlineAndIndent(depth)) {
          return false;
        }
        return Append('}');
      }
      if (position_ >= input_.size() || input_[position_] != ',') {
        error_ = "JSON object entry is missing a comma";
        return false;
      }
      ++position_;
    }
    error_ = "JSON object is not closed";
    return false;
  }

  bool ParseArray(const std::size_t depth) {
    ++position_;
    if (!Append('[')) {
      return false;
    }
    SkipWhitespace();
    if (position_ < input_.size() && input_[position_] == ']') {
      ++position_;
      return Append(']');
    }
    std::size_t entry_count = 0;
    while (position_ < input_.size()) {
      if (entry_count > 0 && !Append(',')) {
        return false;
      }
      if (!NewlineAndIndent(depth + 1) || !ParseValue(depth + 1)) {
        return false;
      }
      ++entry_count;
      SkipWhitespace();
      if (position_ < input_.size() && input_[position_] == ']') {
        ++position_;
        if (!NewlineAndIndent(depth)) {
          return false;
        }
        return Append(']');
      }
      if (position_ >= input_.size() || input_[position_] != ',') {
        error_ = "JSON array entry is missing a comma";
        return false;
      }
      ++position_;
    }
    error_ = "JSON array is not closed";
    return false;
  }

  bool ParseString() {
    const std::size_t start = position_++;
    while (position_ < input_.size()) {
      const auto byte = static_cast<unsigned char>(input_[position_]);
      if (byte == '"') {
        ++position_;
        return Append(input_.substr(start, position_ - start));
      }
      if (byte < 0x20U) {
        error_ = "JSON string contains an unescaped control character";
        return false;
      }
      if (byte != '\\') {
        ++position_;
        continue;
      }
      ++position_;
      if (position_ >= input_.size()) {
        error_ = "JSON string ends inside an escape";
        return false;
      }
      const char escaped = input_[position_++];
      if (std::string_view("\"\\/bfnrt").find(escaped) != std::string_view::npos) {
        continue;
      }
      if (escaped != 'u' || position_ + 4 > input_.size()) {
        error_ = "JSON string contains an invalid escape";
        return false;
      }
      for (std::size_t offset = 0; offset < 4; ++offset) {
        if (HexValue(static_cast<std::uint8_t>(input_[position_ + offset])) < 0) {
          error_ = "JSON string contains an invalid Unicode escape";
          return false;
        }
      }
      position_ += 4;
    }
    error_ = "JSON string is not closed";
    return false;
  }

  bool ParseNumber() {
    const std::size_t start = position_;
    if (position_ < input_.size() && input_[position_] == '-') {
      ++position_;
    }
    if (position_ >= input_.size()) {
      error_ = "JSON number is incomplete";
      return false;
    }
    if (input_[position_] == '0') {
      ++position_;
      if (position_ < input_.size() &&
          std::isdigit(static_cast<unsigned char>(input_[position_])) != 0) {
        error_ = "JSON number has a leading zero";
        return false;
      }
    } else if (input_[position_] >= '1' && input_[position_] <= '9') {
      while (position_ < input_.size() &&
             std::isdigit(static_cast<unsigned char>(input_[position_])) != 0) {
        ++position_;
      }
    } else {
      error_ = "JSON value is invalid";
      return false;
    }
    if (position_ < input_.size() && input_[position_] == '.') {
      ++position_;
      const std::size_t digits = position_;
      while (position_ < input_.size() &&
             std::isdigit(static_cast<unsigned char>(input_[position_])) != 0) {
        ++position_;
      }
      if (position_ == digits) {
        error_ = "JSON number fraction is incomplete";
        return false;
      }
    }
    if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
      ++position_;
      if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-')) {
        ++position_;
      }
      const std::size_t digits = position_;
      while (position_ < input_.size() &&
             std::isdigit(static_cast<unsigned char>(input_[position_])) != 0) {
        ++position_;
      }
      if (position_ == digits) {
        error_ = "JSON number exponent is incomplete";
        return false;
      }
    }
    return Append(input_.substr(start, position_ - start));
  }

  bool ParseLiteral(const std::string_view literal) {
    if (input_.substr(position_, literal.size()) != literal) {
      error_ = "JSON literal is invalid";
      return false;
    }
    position_ += literal.size();
    return Append(literal);
  }

  std::string_view input_;
  bool pretty_ = false;
  std::size_t output_limit_ = 0;
  std::size_t position_ = 0;
  std::size_t tokens_ = 0;
  bool limit_reached_ = false;
  std::string output_;
  std::string error_;
};

DecoderResult FormatJson(std::span<const std::uint8_t> input,
                         const bool pretty,
                         const std::size_t output_limit) {
  const std::string_view text(reinterpret_cast<const char*>(input.data()), input.size());
  return JsonFormatter(text, pretty, output_limit).Run();
}

bool DecodeJsonString(const std::string_view input, std::size_t& position, std::string& output) {
  if (position >= input.size() || input[position] != '"') {
    return false;
  }
  ++position;
  while (position < input.size()) {
    const unsigned char byte = static_cast<unsigned char>(input[position++]);
    if (byte == '"') {
      return true;
    }
    if (byte != '\\') {
      output.push_back(static_cast<char>(byte));
      continue;
    }
    if (position >= input.size()) {
      return false;
    }
    const char escaped = input[position++];
    switch (escaped) {
      case '"':
      case '\\':
      case '/':
        output.push_back(escaped);
        break;
      case 'b':
        output.push_back('\b');
        break;
      case 'f':
        output.push_back('\f');
        break;
      case 'n':
        output.push_back('\n');
        break;
      case 'r':
        output.push_back('\r');
        break;
      case 't':
        output.push_back('\t');
        break;
      case 'u': {
        if (position + 4 > input.size()) {
          return false;
        }
        std::uint32_t code_point = 0;
        for (std::size_t offset = 0; offset < 4; ++offset) {
          const int value = HexValue(static_cast<std::uint8_t>(input[position + offset]));
          if (value < 0) {
            return false;
          }
          code_point = (code_point << 4U) | static_cast<std::uint32_t>(value);
        }
        position += 4;
        if (code_point >= 0xd800U && code_point <= 0xdbffU) {
          if (position + 6 > input.size() || input[position] != '\\' ||
              input[position + 1] != 'u') {
            return false;
          }
          position += 2;
          std::uint32_t low = 0;
          for (std::size_t offset = 0; offset < 4; ++offset) {
            const int value = HexValue(static_cast<std::uint8_t>(input[position + offset]));
            if (value < 0) {
              return false;
            }
            low = (low << 4U) | static_cast<std::uint32_t>(value);
          }
          position += 4;
          if (low < 0xdc00U || low > 0xdfffU) {
            return false;
          }
          code_point = 0x10000U + ((code_point - 0xd800U) << 10U) + (low - 0xdc00U);
        } else if (code_point >= 0xdc00U && code_point <= 0xdfffU) {
          return false;
        }
        if (code_point <= 0x7fU) {
          output.push_back(static_cast<char>(code_point));
        } else if (code_point <= 0x7ffU) {
          output.push_back(static_cast<char>(0xc0U | (code_point >> 6U)));
          output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
        } else if (code_point <= 0xffffU) {
          output.push_back(static_cast<char>(0xe0U | (code_point >> 12U)));
          output.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
          output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
        } else {
          output.push_back(static_cast<char>(0xf0U | (code_point >> 18U)));
          output.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3fU)));
          output.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3fU)));
          output.push_back(static_cast<char>(0x80U | (code_point & 0x3fU)));
        }
        break;
      }
      default:
        return false;
    }
  }
  return false;
}

bool SkipMinifiedJsonValue(const std::string_view input,
                           std::size_t& position,
                           const std::size_t depth) {
  if (position >= input.size() || depth > kDecoderMaxJsonDepth) {
    return false;
  }
  if (input[position] == '"') {
    std::string ignored;
    return DecodeJsonString(input, position, ignored);
  }
  if (input[position] == '{' || input[position] == '[') {
    const char open = input[position++];
    const char close = open == '{' ? '}' : ']';
    if (position < input.size() && input[position] == close) {
      ++position;
      return true;
    }
    while (position < input.size()) {
      if (open == '{') {
        std::string ignored;
        if (!DecodeJsonString(input, position, ignored) || position >= input.size() ||
            input[position++] != ':') {
          return false;
        }
      }
      if (!SkipMinifiedJsonValue(input, position, depth + 1)) {
        return false;
      }
      if (position < input.size() && input[position] == close) {
        ++position;
        return true;
      }
      if (position >= input.size() || input[position++] != ',') {
        return false;
      }
    }
    return false;
  }
  while (position < input.size() && input[position] != ',' && input[position] != '}' &&
         input[position] != ']') {
    ++position;
  }
  return true;
}

std::optional<std::string> TopLevelStringProperty(const std::string_view object,
                                                  const std::string_view property,
                                                  bool& duplicate,
                                                  bool& present) {
  duplicate = false;
  present = false;
  if (object.size() < 2 || object.front() != '{' || object.back() != '}') {
    return std::nullopt;
  }
  std::optional<std::string> result;
  std::size_t position = 1;
  if (position < object.size() && object[position] == '}') {
    return result;
  }
  while (position < object.size() - 1) {
    std::string key;
    if (!DecodeJsonString(object, position, key) || position >= object.size() ||
        object[position++] != ':') {
      return std::nullopt;
    }
    if (key == property) {
      if (present) {
        duplicate = true;
      }
      present = true;
      std::string value;
      const std::size_t value_start = position;
      if (DecodeJsonString(object, position, value)) {
        result = std::move(value);
      } else {
        position = value_start;
        if (!SkipMinifiedJsonValue(object, position, 0)) {
          return std::nullopt;
        }
        result.reset();
      }
    } else if (!SkipMinifiedJsonValue(object, position, 0)) {
      return std::nullopt;
    }
    if (position < object.size() && object[position] == '}') {
      return result;
    }
    if (position >= object.size() || object[position++] != ',') {
      return std::nullopt;
    }
  }
  return std::nullopt;
}

constexpr std::array<std::uint32_t, 64> kSha256RoundConstants = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U,
    0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU,
    0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU,
    0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
    0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U,
    0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U,
    0xc67178f2U,
};

class Sha256 final {
 public:
  void Update(std::span<const std::uint8_t> input) noexcept {
    total_size_ += input.size();
    std::size_t position = 0;
    while (position < input.size()) {
      const std::size_t copied = std::min(input.size() - position, block_.size() - block_size_);
      std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(position), copied,
                  block_.begin() + static_cast<std::ptrdiff_t>(block_size_));
      block_size_ += copied;
      position += copied;
      if (block_size_ == block_.size()) {
        Transform();
        block_size_ = 0;
      }
    }
  }

  std::vector<std::uint8_t> Final() noexcept {
    const std::uint64_t bit_size = static_cast<std::uint64_t>(total_size_) * 8U;
    block_[block_size_++] = 0x80U;
    if (block_size_ > 56) {
      std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_size_), block_.end(), 0U);
      Transform();
      block_size_ = 0;
    }
    std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_size_), block_.begin() + 56, 0U);
    for (std::size_t index = 0; index < 8; ++index) {
      block_[63 - index] = static_cast<std::uint8_t>(bit_size >> (index * 8U));
    }
    Transform();
    std::vector<std::uint8_t> digest(32);
    for (std::size_t index = 0; index < state_.size(); ++index) {
      digest[index * 4] = static_cast<std::uint8_t>(state_[index] >> 24U);
      digest[index * 4 + 1] = static_cast<std::uint8_t>(state_[index] >> 16U);
      digest[index * 4 + 2] = static_cast<std::uint8_t>(state_[index] >> 8U);
      digest[index * 4 + 3] = static_cast<std::uint8_t>(state_[index]);
    }
    return digest;
  }

 private:
  void Transform() noexcept {
    std::array<std::uint32_t, 64> schedule{};
    for (std::size_t index = 0; index < 16; ++index) {
      const std::size_t offset = index * 4;
      schedule[index] = (static_cast<std::uint32_t>(block_[offset]) << 24U) |
                        (static_cast<std::uint32_t>(block_[offset + 1]) << 16U) |
                        (static_cast<std::uint32_t>(block_[offset + 2]) << 8U) |
                        static_cast<std::uint32_t>(block_[offset + 3]);
    }
    for (std::size_t index = 16; index < schedule.size(); ++index) {
      const std::uint32_t s0 = std::rotr(schedule[index - 15], 7) ^
                               std::rotr(schedule[index - 15], 18) ^ (schedule[index - 15] >> 3U);
      const std::uint32_t s1 = std::rotr(schedule[index - 2], 17) ^
                               std::rotr(schedule[index - 2], 19) ^ (schedule[index - 2] >> 10U);
      schedule[index] = schedule[index - 16] + s0 + schedule[index - 7] + s1;
    }
    std::uint32_t a = state_[0];
    std::uint32_t b = state_[1];
    std::uint32_t c = state_[2];
    std::uint32_t d = state_[3];
    std::uint32_t e = state_[4];
    std::uint32_t f = state_[5];
    std::uint32_t g = state_[6];
    std::uint32_t h = state_[7];
    for (std::size_t index = 0; index < schedule.size(); ++index) {
      const std::uint32_t sum1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
      const std::uint32_t choice = (e & f) ^ (~e & g);
      const std::uint32_t first =
          h + sum1 + choice + kSha256RoundConstants[index] + schedule[index];
      const std::uint32_t sum0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
      const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t second = sum0 + majority;
      h = g;
      g = f;
      f = e;
      e = d + first;
      d = c;
      c = b;
      b = a;
      a = first + second;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  std::array<std::uint32_t, 8> state_ = {
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
  };
  std::array<std::uint8_t, 64> block_{};
  std::size_t block_size_ = 0;
  std::size_t total_size_ = 0;
};

constexpr std::array<std::uint64_t, 80> kSha512RoundConstants = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

class Sha512 final {
 public:
  explicit Sha512(const bool sha384) : sha384_(sha384) {
    if (sha384_) {
      state_ = {0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL,
                0x152fecd8f70e5939ULL, 0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
                0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};
    }
  }

  void Update(std::span<const std::uint8_t> input) noexcept {
    total_size_ += input.size();
    std::size_t position = 0;
    while (position < input.size()) {
      const std::size_t copied = std::min(input.size() - position, block_.size() - block_size_);
      std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(position), copied,
                  block_.begin() + static_cast<std::ptrdiff_t>(block_size_));
      block_size_ += copied;
      position += copied;
      if (block_size_ == block_.size()) {
        Transform();
        block_size_ = 0;
      }
    }
  }

  std::vector<std::uint8_t> Final() noexcept {
    const std::uint64_t low_bits = static_cast<std::uint64_t>(total_size_) << 3U;
    const std::uint64_t high_bits = static_cast<std::uint64_t>(total_size_) >> 61U;
    block_[block_size_++] = 0x80U;
    if (block_size_ > 112) {
      std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_size_), block_.end(), 0U);
      Transform();
      block_size_ = 0;
    }
    std::fill(block_.begin() + static_cast<std::ptrdiff_t>(block_size_), block_.begin() + 112, 0U);
    for (std::size_t index = 0; index < 8; ++index) {
      block_[119 - index] = static_cast<std::uint8_t>(high_bits >> (index * 8U));
      block_[127 - index] = static_cast<std::uint8_t>(low_bits >> (index * 8U));
    }
    Transform();
    const std::size_t digest_size = sha384_ ? 48 : 64;
    std::vector<std::uint8_t> digest(digest_size);
    for (std::size_t index = 0; index < digest_size / 8; ++index) {
      for (std::size_t byte = 0; byte < 8; ++byte) {
        digest[index * 8 + byte] = static_cast<std::uint8_t>(state_[index] >> ((7U - byte) * 8U));
      }
    }
    return digest;
  }

 private:
  void Transform() noexcept {
    std::array<std::uint64_t, 80> schedule{};
    for (std::size_t index = 0; index < 16; ++index) {
      const std::size_t offset = index * 8;
      for (std::size_t byte = 0; byte < 8; ++byte) {
        schedule[index] = (schedule[index] << 8U) | block_[offset + byte];
      }
    }
    for (std::size_t index = 16; index < schedule.size(); ++index) {
      const std::uint64_t s0 = std::rotr(schedule[index - 15], 1) ^
                               std::rotr(schedule[index - 15], 8) ^ (schedule[index - 15] >> 7U);
      const std::uint64_t s1 = std::rotr(schedule[index - 2], 19) ^
                               std::rotr(schedule[index - 2], 61) ^ (schedule[index - 2] >> 6U);
      schedule[index] = schedule[index - 16] + s0 + schedule[index - 7] + s1;
    }
    std::uint64_t a = state_[0];
    std::uint64_t b = state_[1];
    std::uint64_t c = state_[2];
    std::uint64_t d = state_[3];
    std::uint64_t e = state_[4];
    std::uint64_t f = state_[5];
    std::uint64_t g = state_[6];
    std::uint64_t h = state_[7];
    for (std::size_t index = 0; index < schedule.size(); ++index) {
      const std::uint64_t sum1 = std::rotr(e, 14) ^ std::rotr(e, 18) ^ std::rotr(e, 41);
      const std::uint64_t choice = (e & f) ^ (~e & g);
      const std::uint64_t first =
          h + sum1 + choice + kSha512RoundConstants[index] + schedule[index];
      const std::uint64_t sum0 = std::rotr(a, 28) ^ std::rotr(a, 34) ^ std::rotr(a, 39);
      const std::uint64_t majority = (a & b) ^ (a & c) ^ (b & c);
      const std::uint64_t second = sum0 + majority;
      h = g;
      g = f;
      f = e;
      e = d + first;
      d = c;
      c = b;
      b = a;
      a = first + second;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

  bool sha384_ = false;
  std::array<std::uint64_t, 8> state_ = {
      0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
      0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
  };
  std::array<std::uint8_t, 128> block_{};
  std::size_t block_size_ = 0;
  std::size_t total_size_ = 0;
};

std::vector<std::uint8_t> Sha2Digest(const JwtAlgorithm algorithm,
                                     std::span<const std::uint8_t> input) {
  if (algorithm == JwtAlgorithm::kHs256) {
    Sha256 hash;
    hash.Update(input);
    return hash.Final();
  }
  Sha512 hash(algorithm == JwtAlgorithm::kHs384);
  hash.Update(input);
  return hash.Final();
}

std::vector<std::uint8_t> HmacSha2(const JwtAlgorithm algorithm,
                                   std::span<const std::uint8_t> key,
                                   std::span<const std::uint8_t> input) {
  const std::size_t block_size = algorithm == JwtAlgorithm::kHs256 ? 64 : 128;
  std::vector<std::uint8_t> normalized_key;
  if (key.size() > block_size) {
    normalized_key = Sha2Digest(algorithm, key);
  } else {
    normalized_key.assign(key.begin(), key.end());
  }
  normalized_key.resize(block_size, 0);
  std::vector<std::uint8_t> inner(block_size + input.size());
  std::vector<std::uint8_t> outer(block_size);
  for (std::size_t index = 0; index < block_size; ++index) {
    inner[index] = normalized_key[index] ^ 0x36U;
    outer[index] = normalized_key[index] ^ 0x5cU;
  }
  std::copy(input.begin(), input.end(), inner.begin() + static_cast<std::ptrdiff_t>(block_size));
  const std::vector<std::uint8_t> inner_digest = Sha2Digest(algorithm, inner);
  outer.insert(outer.end(), inner_digest.begin(), inner_digest.end());
  return Sha2Digest(algorithm, outer);
}

bool ConstantTimeEqual(std::span<const std::uint8_t> left,
                       std::span<const std::uint8_t> right) noexcept {
  std::size_t difference = left.size() ^ right.size();
  const std::size_t maximum = std::max(left.size(), right.size());
  for (std::size_t index = 0; index < maximum; ++index) {
    const std::uint8_t left_byte = index < left.size() ? left[index] : 0;
    const std::uint8_t right_byte = index < right.size() ? right[index] : 0;
    difference |= static_cast<std::size_t>(left_byte ^ right_byte);
  }
  return difference == 0;
}

std::string JsonEscape(const std::string_view input) {
  std::string output;
  output.reserve(input.size() + 8);
  constexpr char kHex[] = "0123456789abcdef";
  for (const char raw_byte : input) {
    const auto byte = static_cast<unsigned char>(raw_byte);
    switch (byte) {
      case '"':
        output += "\\\"";
        break;
      case '\\':
        output += "\\\\";
        break;
      case '\b':
        output += "\\b";
        break;
      case '\f':
        output += "\\f";
        break;
      case '\n':
        output += "\\n";
        break;
      case '\r':
        output += "\\r";
        break;
      case '\t':
        output += "\\t";
        break;
      default:
        if (byte < 0x20U) {
          output += "\\u00";
          output.push_back(kHex[byte >> 4U]);
          output.push_back(kHex[byte & 0x0fU]);
        } else {
          output.push_back(static_cast<char>(byte));
        }
        break;
    }
  }
  return output;
}

std::string ByteVectorToString(const std::vector<std::uint8_t>& input) {
  return std::string(reinterpret_cast<const char*>(input.data()), input.size());
}

std::string SignatureStatusName(const JwtSignatureStatus status) {
  switch (status) {
    case JwtSignatureStatus::kNotChecked:
      return "not_checked";
    case JwtSignatureStatus::kVerified:
      return "verified";
    case JwtSignatureStatus::kInvalid:
      return "invalid";
    case JwtSignatureStatus::kUnsigned:
      return "unsigned";
    case JwtSignatureStatus::kUnsupported:
      return "unsupported";
  }
  return "unsupported";
}

JwtAlgorithm JwtAlgorithmFromName(const std::string_view name) noexcept {
  if (name == "none") {
    return JwtAlgorithm::kNone;
  }
  if (name == "HS256") {
    return JwtAlgorithm::kHs256;
  }
  if (name == "HS384") {
    return JwtAlgorithm::kHs384;
  }
  if (name == "HS512") {
    return JwtAlgorithm::kHs512;
  }
  return JwtAlgorithm::kUnsupported;
}

std::string_view JwtAlgorithmName(const JwtAlgorithm algorithm) noexcept {
  switch (algorithm) {
    case JwtAlgorithm::kNone:
      return "none";
    case JwtAlgorithm::kHs256:
      return "HS256";
    case JwtAlgorithm::kHs384:
      return "HS384";
    case JwtAlgorithm::kHs512:
      return "HS512";
    case JwtAlgorithm::kUnsupported:
      return "unsupported";
  }
  return "unsupported";
}

JwtInspection JwtFailure(std::string message) {
  JwtInspection inspection;
  inspection.status = DecoderStatus::kInvalidInput;
  inspection.error = std::move(message);
  return inspection;
}

}  // namespace

std::optional<DecoderOperation> DecoderOperationFromName(const std::string_view name) noexcept {
  constexpr std::array<std::pair<std::string_view, DecoderOperation>, 18> kOperations = {{
      {"base64-encode", DecoderOperation::kBase64Encode},
      {"base64-decode", DecoderOperation::kBase64Decode},
      {"base64url-encode", DecoderOperation::kBase64UrlEncode},
      {"base64url-decode", DecoderOperation::kBase64UrlDecode},
      {"hex-encode", DecoderOperation::kHexEncode},
      {"hex-decode", DecoderOperation::kHexDecode},
      {"url-encode", DecoderOperation::kUrlEncode},
      {"url-decode", DecoderOperation::kUrlDecode},
      {"base36-encode", DecoderOperation::kBase36Encode},
      {"base36-decode", DecoderOperation::kBase36Decode},
      {"gzip-compress", DecoderOperation::kGzipCompress},
      {"gzip-decompress", DecoderOperation::kGzipDecompress},
      {"zlib-compress", DecoderOperation::kZlibCompress},
      {"zlib-decompress", DecoderOperation::kZlibDecompress},
      {"deflate-compress", DecoderOperation::kDeflateCompress},
      {"deflate-decompress", DecoderOperation::kDeflateDecompress},
      {"json-pretty", DecoderOperation::kJsonPretty},
      {"json-minify", DecoderOperation::kJsonMinify},
  }};
  const auto iterator = std::find_if(kOperations.begin(), kOperations.end(),
                                     [name](const auto& item) { return item.first == name; });
  return iterator == kOperations.end() ? std::nullopt
                                       : std::optional<DecoderOperation>(iterator->second);
}

std::string_view DecoderOperationName(const DecoderOperation operation) noexcept {
  switch (operation) {
    case DecoderOperation::kBase64Encode:
      return "base64-encode";
    case DecoderOperation::kBase64Decode:
      return "base64-decode";
    case DecoderOperation::kBase64UrlEncode:
      return "base64url-encode";
    case DecoderOperation::kBase64UrlDecode:
      return "base64url-decode";
    case DecoderOperation::kHexEncode:
      return "hex-encode";
    case DecoderOperation::kHexDecode:
      return "hex-decode";
    case DecoderOperation::kUrlEncode:
      return "url-encode";
    case DecoderOperation::kUrlDecode:
      return "url-decode";
    case DecoderOperation::kBase36Encode:
      return "base36-encode";
    case DecoderOperation::kBase36Decode:
      return "base36-decode";
    case DecoderOperation::kGzipCompress:
      return "gzip-compress";
    case DecoderOperation::kGzipDecompress:
      return "gzip-decompress";
    case DecoderOperation::kZlibCompress:
      return "zlib-compress";
    case DecoderOperation::kZlibDecompress:
      return "zlib-decompress";
    case DecoderOperation::kDeflateCompress:
      return "deflate-compress";
    case DecoderOperation::kDeflateDecompress:
      return "deflate-decompress";
    case DecoderOperation::kJsonPretty:
      return "json-pretty";
    case DecoderOperation::kJsonMinify:
      return "json-minify";
  }
  return "unsupported";
}

DecoderResult TransformBytes(const DecoderOperation operation,
                             const std::span<const std::uint8_t> input,
                             const std::size_t output_limit) {
  if (input.size() > kDecoderMaxInputBytes || output_limit == 0 ||
      output_limit > kDecoderMaxOutputBytes) {
    return Failure(DecoderStatus::kInvalidInput, "Decoder byte limits are invalid or exceeded");
  }
  switch (operation) {
    case DecoderOperation::kBase64Encode: {
      const std::size_t output_size = ((input.size() + 2) / 3) * 4;
      if (output_size > output_limit) {
        return Failure(DecoderStatus::kOutputLimit,
                       "Encoded output exceeds the configured byte limit");
      }
      return Success(Base64Encode(input, false, true));
    }
    case DecoderOperation::kBase64Decode:
      return Base64Decode(input, false, output_limit);
    case DecoderOperation::kBase64UrlEncode: {
      const std::size_t output_size = (input.size() * 4 + 2) / 3;
      if (output_size > output_limit) {
        return Failure(DecoderStatus::kOutputLimit,
                       "Encoded output exceeds the configured byte limit");
      }
      return Success(Base64Encode(input, true, false));
    }
    case DecoderOperation::kBase64UrlDecode:
      return Base64Decode(input, true, output_limit);
    case DecoderOperation::kHexEncode: {
      if (input.size() > output_limit / 2) {
        return Failure(DecoderStatus::kOutputLimit, "Hex output exceeds the configured byte limit");
      }
      constexpr char kHex[] = "0123456789abcdef";
      std::vector<std::uint8_t> output(input.size() * 2);
      for (std::size_t index = 0; index < input.size(); ++index) {
        output[index * 2] = static_cast<std::uint8_t>(kHex[input[index] >> 4U]);
        output[index * 2 + 1] = static_cast<std::uint8_t>(kHex[input[index] & 0x0fU]);
      }
      return Success(std::move(output));
    }
    case DecoderOperation::kHexDecode:
      return HexDecode(input, output_limit);
    case DecoderOperation::kUrlEncode:
      return UrlEncode(input, output_limit);
    case DecoderOperation::kUrlDecode:
      return UrlDecode(input, output_limit);
    case DecoderOperation::kBase36Encode:
      if (input.size() > 4U << 10U) {
        return Failure(DecoderStatus::kInvalidInput,
                       "Base36 integers are limited to 4 KiB of digits");
      }
      return DecimalToBase36(input, output_limit);
    case DecoderOperation::kBase36Decode:
      if (input.size() > 4U << 10U) {
        return Failure(DecoderStatus::kInvalidInput,
                       "Base36 integers are limited to 4 KiB of digits");
      }
      return Base36ToDecimal(input, output_limit);
    case DecoderOperation::kGzipCompress:
      return ZlibTransform(input, true, MAX_WBITS + 16, output_limit);
    case DecoderOperation::kGzipDecompress:
      return ZlibTransform(input, false, MAX_WBITS + 16, output_limit);
    case DecoderOperation::kZlibCompress:
      return ZlibTransform(input, true, MAX_WBITS, output_limit);
    case DecoderOperation::kZlibDecompress:
      return ZlibTransform(input, false, MAX_WBITS, output_limit);
    case DecoderOperation::kDeflateCompress:
      return ZlibTransform(input, true, -MAX_WBITS, output_limit);
    case DecoderOperation::kDeflateDecompress:
      return ZlibTransform(input, false, -MAX_WBITS, output_limit);
    case DecoderOperation::kJsonPretty:
      return FormatJson(input, true, output_limit);
    case DecoderOperation::kJsonMinify:
      return FormatJson(input, false, output_limit);
  }
  return Failure(DecoderStatus::kUnsupported, "Decoder operation is unsupported");
}

JwtInspection InspectJwt(const std::string_view token) {
  if (token.empty() || token.size() > kDecoderMaxJwtBytes) {
    return JwtFailure("JWT must contain between 1 byte and 64 KiB");
  }
  const std::size_t first_dot = token.find('.');
  const std::size_t second_dot =
      first_dot == std::string_view::npos ? std::string_view::npos : token.find('.', first_dot + 1);
  if (first_dot == std::string_view::npos || second_dot == std::string_view::npos ||
      token.find('.', second_dot + 1) != std::string_view::npos || first_dot == 0 ||
      second_dot == first_dot + 1) {
    return JwtFailure("JWT compact serialization must contain exactly three segments");
  }
  const auto decode_segment = [](const std::string_view segment, const std::size_t limit) {
    return Base64Decode(std::span<const std::uint8_t>(
                            reinterpret_cast<const std::uint8_t*>(segment.data()), segment.size()),
                        true, limit);
  };
  DecoderResult header = decode_segment(token.substr(0, first_dot), 8U << 10U);
  DecoderResult payload =
      decode_segment(token.substr(first_dot + 1, second_dot - first_dot - 1), 56U << 10U);
  DecoderResult signature = decode_segment(token.substr(second_dot + 1), 128);
  if (header.status != DecoderStatus::kOk) {
    return JwtFailure("JWT header is not canonical Base64URL: " + header.error);
  }
  if (payload.status != DecoderStatus::kOk) {
    return JwtFailure("JWT payload is not canonical Base64URL: " + payload.error);
  }
  if (signature.status != DecoderStatus::kOk) {
    return JwtFailure("JWT signature is not canonical Base64URL: " + signature.error);
  }
  DecoderResult header_minified = FormatJson(header.output, false, 8U << 10U);
  DecoderResult payload_minified = FormatJson(payload.output, false, 56U << 10U);
  if (header_minified.status != DecoderStatus::kOk || header_minified.output.size() < 2 ||
      header_minified.output.front() != '{' || header_minified.output.back() != '}') {
    return JwtFailure("JWT header must be a bounded JSON object");
  }
  if (payload_minified.status != DecoderStatus::kOk || payload_minified.output.size() < 2 ||
      payload_minified.output.front() != '{' || payload_minified.output.back() != '}') {
    return JwtFailure("JWT payload must be a bounded JSON object");
  }
  const std::string header_compact = ByteVectorToString(header_minified.output);
  bool duplicate = false;
  bool present = false;
  const std::optional<std::string> algorithm =
      TopLevelStringProperty(header_compact, "alg", duplicate, present);
  if (!present || duplicate || !algorithm.has_value() || algorithm->empty() ||
      algorithm->size() > 32) {
    return JwtFailure("JWT header must contain one bounded string algorithm");
  }
  DecoderResult header_pretty = FormatJson(header.output, true, 16U << 10U);
  DecoderResult payload_pretty = FormatJson(payload.output, true, 112U << 10U);
  if (header_pretty.status != DecoderStatus::kOk || payload_pretty.status != DecoderStatus::kOk) {
    return JwtFailure("JWT JSON display exceeds the bounded output limit");
  }
  const JwtAlgorithm algorithm_kind = JwtAlgorithmFromName(*algorithm);
  JwtSignatureStatus signature_status = JwtSignatureStatus::kNotChecked;
  if (algorithm_kind == JwtAlgorithm::kNone) {
    signature_status =
        signature.output.empty() ? JwtSignatureStatus::kUnsigned : JwtSignatureStatus::kInvalid;
  } else if (algorithm_kind == JwtAlgorithm::kUnsupported) {
    signature_status = JwtSignatureStatus::kUnsupported;
  }
  return {
      .status = DecoderStatus::kOk,
      .error = {},
      .algorithm = *algorithm,
      .algorithm_kind = algorithm_kind,
      .signature_status = signature_status,
      .header_json = ByteVectorToString(header_pretty.output),
      .payload_json = ByteVectorToString(payload_pretty.output),
      .token_bytes = token.size(),
      .signature_bytes = signature.output.size(),
  };
}

JwtInspection VerifyJwt(const std::string_view token, const std::span<const std::uint8_t> secret) {
  JwtInspection inspection = InspectJwt(token);
  if (inspection.status != DecoderStatus::kOk) {
    return inspection;
  }
  if (inspection.algorithm_kind == JwtAlgorithm::kNone) {
    inspection.error = "Unsigned JWTs do not have a verifiable signature";
    return inspection;
  }
  if (inspection.algorithm_kind == JwtAlgorithm::kUnsupported) {
    inspection.error = "Only HS256, HS384, and HS512 signatures can be verified locally";
    return inspection;
  }
  if (secret.empty() || secret.size() > kDecoderMaxSecretBytes) {
    inspection.status = DecoderStatus::kInvalidInput;
    inspection.error = "JWT HMAC secret must contain between 1 byte and 4 KiB";
    return inspection;
  }
  const std::size_t second_dot = token.find('.', token.find('.') + 1);
  DecoderResult signature =
      Base64Decode(std::span<const std::uint8_t>(
                       reinterpret_cast<const std::uint8_t*>(token.data() + second_dot + 1),
                       token.size() - second_dot - 1),
                   true, 128);
  const auto signing_input = std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(token.data()), second_dot);
  const std::vector<std::uint8_t> expected =
      HmacSha2(inspection.algorithm_kind, secret, signing_input);
  inspection.signature_status =
      signature.status == DecoderStatus::kOk && ConstantTimeEqual(expected, signature.output)
          ? JwtSignatureStatus::kVerified
          : JwtSignatureStatus::kInvalid;
  return inspection;
}

JwtCreation CreateJwt(const std::string_view payload_json,
                      const JwtAlgorithm algorithm,
                      const std::span<const std::uint8_t> secret,
                      const std::optional<std::uint64_t> expires_at) {
  if (payload_json.empty() || payload_json.size() > 56U << 10U) {
    return {.status = DecoderStatus::kInvalidInput,
            .error = "JWT payload must contain between 1 byte and 56 KiB",
            .token = {}};
  }
  if (algorithm == JwtAlgorithm::kUnsupported ||
      (algorithm == JwtAlgorithm::kNone && !secret.empty()) ||
      (algorithm != JwtAlgorithm::kNone &&
       (secret.empty() || secret.size() > kDecoderMaxSecretBytes))) {
    return {.status = DecoderStatus::kInvalidInput,
            .error = "JWT creation algorithm or HMAC secret is invalid",
            .token = {}};
  }
  const auto payload_bytes = std::span<const std::uint8_t>(
      reinterpret_cast<const std::uint8_t*>(payload_json.data()), payload_json.size());
  DecoderResult compact_result = FormatJson(payload_bytes, false, 56U << 10U);
  if (compact_result.status != DecoderStatus::kOk || compact_result.output.size() < 2 ||
      compact_result.output.front() != '{' || compact_result.output.back() != '}') {
    return {.status = DecoderStatus::kInvalidInput,
            .error = "JWT payload must be a bounded JSON object",
            .token = {}};
  }
  std::string payload = ByteVectorToString(compact_result.output);
  if (expires_at.has_value()) {
    bool duplicate = false;
    bool present = false;
    static_cast<void>(TopLevelStringProperty(payload, "exp", duplicate, present));
    if (present) {
      return {.status = DecoderStatus::kInvalidInput,
              .error = "Set either payload exp or expires-in, not both",
              .token = {}};
    }
    const std::string member = "\"exp\":" + std::to_string(*expires_at);
    payload.insert(payload.size() - 1, payload.size() == 2 ? member : "," + member);
  }
  const std::string header =
      "{\"alg\":\"" + std::string(JwtAlgorithmName(algorithm)) + "\",\"typ\":\"JWT\"}";
  const auto header_encoded =
      Base64Encode(std::span<const std::uint8_t>(
                       reinterpret_cast<const std::uint8_t*>(header.data()), header.size()),
                   true, false);
  const auto payload_encoded =
      Base64Encode(std::span<const std::uint8_t>(
                       reinterpret_cast<const std::uint8_t*>(payload.data()), payload.size()),
                   true, false);
  std::string signing_input(reinterpret_cast<const char*>(header_encoded.data()),
                            header_encoded.size());
  signing_input.push_back('.');
  signing_input.append(reinterpret_cast<const char*>(payload_encoded.data()),
                       payload_encoded.size());
  std::vector<std::uint8_t> signature;
  if (algorithm != JwtAlgorithm::kNone) {
    signature = HmacSha2(
        algorithm, secret,
        std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(signing_input.data()),
                                      signing_input.size()));
  }
  const auto signature_encoded = Base64Encode(signature, true, false);
  std::string token = signing_input + "." +
                      std::string(reinterpret_cast<const char*>(signature_encoded.data()),
                                  signature_encoded.size());
  if (token.size() > kDecoderMaxJwtBytes) {
    return {.status = DecoderStatus::kOutputLimit,
            .error = "Created JWT exceeds the 64 KiB token limit",
            .token = {}};
  }
  return {.status = DecoderStatus::kOk, .error = {}, .token = std::move(token)};
}

std::string JwtInspectionToJson(const JwtInspection& inspection) {
  std::ostringstream output;
  output << "{\"protocol_version\":1,\"ok\":"
         << (inspection.status == DecoderStatus::kOk ? "true" : "false") << ",\"algorithm\":\""
         << JsonEscape(inspection.algorithm) << "\",\"signature_status\":\""
         << SignatureStatusName(inspection.signature_status) << "\",\"header_json\":\""
         << JsonEscape(inspection.header_json) << "\",\"payload_json\":\""
         << JsonEscape(inspection.payload_json) << "\",\"token_bytes\":" << inspection.token_bytes
         << ",\"signature_bytes\":" << inspection.signature_bytes << ",\"error\":";
  if (inspection.error.empty()) {
    output << "null";
  } else {
    output << "\"" << JsonEscape(inspection.error) << "\"";
  }
  output << '}';
  return output.str();
}

std::string JwtCreationToJson(const JwtCreation& creation) {
  std::ostringstream output;
  output << "{\"protocol_version\":1,\"ok\":"
         << (creation.status == DecoderStatus::kOk ? "true" : "false") << ",\"token\":\""
         << JsonEscape(creation.token) << "\",\"error\":";
  if (creation.error.empty()) {
    output << "null";
  } else {
    output << "\"" << JsonEscape(creation.error) << "\"";
  }
  output << '}';
  return output.str();
}

}  // namespace reb
