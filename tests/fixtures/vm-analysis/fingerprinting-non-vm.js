export function collectEnvironment(canvas) {
  return {
    image: canvas.toDataURL(),
    language: navigator.language,
    hardwareConcurrency: navigator.hardwareConcurrency,
    webdriver: navigator.webdriver,
  };
}
