function rotatePixels(bytes) {
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = (bytes[index] + 1) & 255;
  }
}

function labelStatus(status) {
  switch (status) {
    case 1: return "ready";
    case 2: return "done";
    default: return "unknown";
  }
}

function reportProgress(programCounter) {
  return `progress:${programCounter}`;
}

function palette() {
  return new Uint8Array([3, 14, 17, 40, 5, 9]);
}
