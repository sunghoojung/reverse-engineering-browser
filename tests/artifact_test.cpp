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
  header.execution_context_id = 3;
  header.capture_origin = reb::ArtifactCaptureOrigin::kNativeWasmGuest;
  header.frame_id = 4;
  header.parent_artifact_id = 5;
  header.creator_event_id = 6;
  for (const auto kind :
       {reb::ArtifactKind::kBytecodeBuffer, reb::ArtifactKind::kWasmGuestAdapter}) {
    header.kind = kind;
    if (!reb::IsValidArtifactHeader(header))
      return 1;
  }
  if (std::string_view(reb::ArtifactKindName(header.kind)) != "wasm_guest_adapter" ||
      std::string_view(reb::ArtifactCaptureOriginName(header.capture_origin)) !=
          "native_wasm_guest")
    return 1;
  header.execution_context_id = 0;
  if (reb::IsValidArtifactHeader(header))
    return 1;
  header.execution_context_id = 3;
  for (const auto kind :
       {reb::ArtifactKind::kJavaScript, reb::ArtifactKind::kWasm, reb::ArtifactKind::kSourceMap}) {
    header.kind = kind;
    if (reb::IsValidArtifactHeader(header))
      return 1;
  }
  return 0;
}
