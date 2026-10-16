#include <iostream>
#include <string_view>

#include "reb/artifact.hpp"

int main() {
  reb::ArtifactHeader header;
  header.kind = reb::ArtifactKind::kBytecodeBuffer;
  header.session_id = 1;
  header.artifact_id = 2;
  header.content_size = 32;
  header.url_size = 24;
  header.mime_type_size = 24;
  header.execution_context_id = 3;
  header.capture_origin = reb::ArtifactCaptureOrigin::kRuntimeTypedArray;
  if (!reb::IsValidArtifactHeader(header) ||
      std::string_view(reb::ArtifactKindName(header.kind)) != "bytecode_buffer" ||
      std::string_view(reb::ArtifactCaptureOriginName(header.capture_origin)) !=
          "runtime_typed_array") {
    std::cerr << "runtime typed-array artifact contract failed\n";
    return 1;
  }
  header.kind = reb::ArtifactKind::kJavaScript;
  if (reb::IsValidArtifactHeader(header)) {
    std::cerr << "mismatched runtime typed-array origin accepted\n";
    return 1;
  }
  header.capture_origin = reb::ArtifactCaptureOrigin::kRuntimeAllocatingScript;
  if (!reb::IsValidArtifactHeader(header) ||
      std::string_view(reb::ArtifactCaptureOriginName(header.capture_origin)) !=
          "runtime_allocating_script") {
    std::cerr << "allocating-script origin rejected\n";
    return 1;
  }
  header.execution_context_id = 0;
  if (reb::IsValidArtifactHeader(header)) {
    std::cerr << "allocating-script origin accepted without execution context\n";
    return 1;
  }
  return 0;
}
