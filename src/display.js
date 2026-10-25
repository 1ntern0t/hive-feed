// Render untrusted strings for terminals/logs: escapes C0/C1 control chars
// (including ESC, so ANSI sequences cannot move the cursor or recolor output),
// bidi overrides, and truncates. The result is still DATA, never instructions.
const BAD = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;

export function safeDisplay(s, max = 500) {
  const str = String(s);
  const cut = str.length > max ? str.slice(0, max) + '…[truncated]' : str;
  return cut.replace(BAD, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}
