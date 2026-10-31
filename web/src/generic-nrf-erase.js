// Reviewed, board-neutral nRF52 erase APPLICATIONS. Match the actual BIN,
// never its ZIP name or a caller-supplied description. Board-specific QSPI
// formatters and bootloader/SoftDevice replacements do not belong here.
const payloads = new Map([
  ['f17500b598ce53d4d4183f6bd20e06e9bf2bd3468d9a22ff3af7f148bb0dfc0c','official SoftDevice v6 erase payload'],
  ['01f8d553e5ce865312fcfe3ddf1eb06f10ed7ca6bd4f34dd81e58b6f8400be8e','official SoftDevice v7 erase payload'],
]);

export const genericNrfEraseIntent = payloadHash => payloads.get(payloadHash) || null;
