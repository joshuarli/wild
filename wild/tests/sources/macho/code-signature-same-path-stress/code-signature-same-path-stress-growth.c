// The test harness selectively includes this input between same-path links. Initialising the
// first byte keeps the entire 2 MiB array materialised in __DATA rather than becoming BSS.
__attribute__((used)) volatile unsigned char code_signature_growth_payload[2 * 1024 * 1024] = {
    1,
};
