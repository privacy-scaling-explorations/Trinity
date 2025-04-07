/**
 * Converts a number to a 16-bit little-endian Uint8Array
 */
export function intToUint8Array2(value: number): Uint8Array {
  const arr = new Uint8Array(2);
  arr[0] = value & 0xff; // Low byte (little-endian)
  arr[1] = (value >> 8) & 0xff; // High byte (little-endian)
  return arr;
}
