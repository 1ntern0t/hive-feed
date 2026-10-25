// Canonical JSON: object keys sorted by UTF-16 code unit order, no
// whitespace, only strings, safe integers, booleans, arrays and objects.
// Floats, null, NaN, undefined and non-plain objects are rejected so that a
// value has exactly one byte representation.

export function canonicalize(value) {
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new TypeError('canonical: only safe integers allowed');
    return String(value);
  }
  if (Array.isArray(value)) return '[' + value.map(canonicalize).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw new TypeError('canonical: plain objects only');
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => {
      if (value[k] === undefined) throw new TypeError('canonical: undefined value for ' + k);
      return JSON.stringify(k) + ':' + canonicalize(value[k]);
    }).join(',') + '}';
  }
  throw new TypeError('canonical: unsupported value type');
}
