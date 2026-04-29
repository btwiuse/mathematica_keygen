import * as readline from "node:readline";

const hashCode1 = 0b1000001011100001; // 33505 / 0x82E1
const hashCode2 = 0b1000001100100101; // 33573 / 0x8325
const magicNumber = 59222;

// MathPass holds the state for a single keygen operation.
class MathPass {
  version: [number, number, number] = [0, 0, 0];
  mathID = "";
  activationKey = "";
  password = "";
}

// newMathPass creates a MathPass for the given Math ID and version.
// If customKey is non-empty and matches the required format it is used;
// otherwise a random activation key is generated.
function newMathPass(mathID: string, version: string, customKey: string): MathPass {
  const mp = new MathPass();
  mp.version = parseVersion(version);
  setMathID(mp, mathID);
  const keyFmt = activationKeyFormat(mp);
  if (customKey !== "" && checkFormat(keyFmt, customKey)) {
    mp.activationKey = customKey;
  } else {
    mp.activationKey = randomActivationKey(keyFmt);
  }
  return mp;
}

function versionAtLeast(mp: MathPass, major: number, minor: number, patch: number): boolean {
  const v = mp.version;
  return (
    v[0] > major ||
    (v[0] === major && v[1] > minor) ||
    (v[0] === major && v[1] === minor && v[2] >= patch)
  );
}

function activationKeyFormat(mp: MathPass): string {
  if (versionAtLeast(mp, 14, 1, 0)) {
    return "xxxx-xxxx-aaaaaa";
  }
  return "xxxx-xxxx-xxxxxx";
}

function setMathID(mp: MathPass, mathID: string): boolean {
  if (checkFormat("xxxx-xxxxx-xxxxx", mathID)) {
    mp.mathID = mathID;
    return true;
  }
  return false;
}

// generatePassword generates the password for the given math number and expiry date.
// Empty strings fall back to the defaults ("800001" and 999 days from now respectively).
function generatePassword(mp: MathPass, mathNum: string, expireDate: string): boolean {
  if (mathNum === "") {
    mathNum = "800001";
  }
  if (expireDate === "") {
    expireDate = dateAfter(999);
  }
  if (versionAtLeast(mp, 14, 1, 0)) {
    return generatePasswordV14_1_0(mp, mathNum, expireDate);
  }
  return false;
}

function generatePasswordV14_1_0(mp: MathPass, mathNum: string, expireDate: string): boolean {
  const strVal = mp.mathID + "@" + expireDate + "$" + mathNum + "&" + mp.activationKey;
  const chars = reverseString(strVal);
  let hc = magicNumber;
  const n0 = encodingCharacters(hashCode1, hc, chars);
  const n1 = (n0 + 0x72fa) % 65536;
  hc = encodingHash(n1);
  const n2 = encodingCharacters(hashCode2, hc, chars);
  mp.password = constructPassword(n1, n2) + "::" + mathNum + ":" + expireDate;
  return true;
}

// hasher processes one byte through the CRC-like hash step.
function hasher(hasherCode: number, hashVal: number, byteVal: number): number {
  for (let i = 0; i < 8; i++) {
    const bit = byteVal & 1;
    if (hashVal % 2 === bit) {
      hashVal >>= 1;
    } else {
      hashVal >>= 1;
      hashVal ^= hasherCode;
    }
    byteVal >>= 1;
  }
  return hashVal;
}

// splitHex maps a 16-bit value to a 5-digit decimal representation and returns
// the digits from least-significant to most-significant (index 0 = ones place).
function splitHex(hexVal: number): [number, number, number, number, number] {
  let n = Math.floor((hexVal * 99999.0) / 0xffff);
  const d: [number, number, number, number, number] = [0, 0, 0, 0, 0];
  for (let i = 0; i < 5; i++) {
    d[i] = n % 10;
    n = Math.floor(n / 10);
  }
  return d;
}

// encodingHash computes the secondary hash value derived from n1.
function encodingHash(n1: number): number {
  let n = Math.floor((n1 * 99999.0) / 0xffff);
  const n01 = n % 100;
  n -= n01;
  const n2 = n % 1000;
  n -= n2;
  n += n01 * 10 + Math.floor(n2 / 100);
  const temp = Math.ceil((n * 65535.0) / 99999);
  return hasher(hashCode2, hasher(hashCode2, 0, temp & 0xff), temp >> 8);
}

// encodingCharacters searches for a 16-bit value whose two bytes, appended to
// the hashed character stream, produce 0xA5B6.
function encodingCharacters(hasherCode: number, hashVal: number, chars: number[]): number {
  for (const c of chars) {
    hashVal = hasher(hasherCode, hashVal, c);
  }
  let c1 = 0;
  let c2 = 0;
  for (c1 = 0; c1 < 256; c1++) {
    for (c2 = 0; c2 < 256; c2++) {
      if (hasher(hasherCode, hasher(hasherCode, hashVal, c1), c2) === 0xa5b6) {
        return c1 | (c2 << 8);
      }
    }
  }
  return c1 | (c2 << 8);
}

// constructPassword assembles the printable password from n1 and n2.
//
// Python uses splitHex(n)[::-1] so its index 0 is the most-significant digit.
// Go's splitHex stores the least-significant digit at index 0, so we reverse
// the mapping: Python index i  →  Go index (4 - i).
//
// Password pattern (Python indices, both arrays reversed):
//   n2[3] n1[3] n1[1] n1[0] - n2[4] n1[2] n2[0] - n2[2] n1[4] n2[1]
//
// Translated to Go (splitHex, LSB-first) indices:
//   n2[1] n1[1] n1[3] n1[4] - n2[0] n1[2] n2[4] - n2[2] n1[0] n2[3]
function constructPassword(n1: number, n2: number): string {
  const a = splitHex(n1); // a[0]=ones, a[4]=ten-thousands
  const b = splitHex(n2);
  return (
    `${b[1]}${a[1]}${a[3]}${a[4]}-${b[0]}${a[2]}${b[4]}-${b[2]}${a[0]}${b[3]}`
  );
}

// reverseString returns the byte values of s in reverse order.
function reverseString(s: string): number[] {
  const out: number[] = new Array(s.length);
  for (let i = 0; i < s.length; i++) {
    out[i] = s.charCodeAt(s.length - 1 - i);
  }
  return out;
}

// checkFormat validates s against a format string where:
//   'x' = ASCII digit, 'a' = uppercase letter, 'b' = digit or uppercase letter,
//   any other character must match literally.
function checkFormat(format: string, s: string): boolean {
  if (format.length !== s.length) {
    return false;
  }
  for (let i = 0; i < format.length; i++) {
    switch (format[i]) {
      case "x":
        if (s[i] < "0" || s[i] > "9") return false;
        break;
      case "a":
        if (s[i] < "A" || s[i] > "Z") return false;
        break;
      case "b":
        if (!((s[i] >= "0" && s[i] <= "9") || (s[i] >= "A" && s[i] <= "Z")))
          return false;
        break;
      default:
        if (format[i] !== s[i]) return false;
    }
  }
  return true;
}

// randomActivationKey generates a random key matching the given format string.
function randomActivationKey(format: string): string {
  let result = "";
  for (let i = 0; i < format.length; i++) {
    switch (format[i]) {
      case "x":
        result += String.fromCharCode("0".charCodeAt(0) + Math.floor(Math.random() * 10));
        break;
      case "a":
        result += String.fromCharCode("A".charCodeAt(0) + Math.floor(Math.random() * 26));
        break;
      default:
        result += format[i];
    }
  }
  return result;
}

// parseVersion converts "14.1.0" into [14, 1, 0].
function parseVersion(version: string): [number, number, number] {
  const parts = version.split(".");
  const v: [number, number, number] = [0, 0, 0];
  for (let i = 0; i < Math.min(parts.length, 3); i++) {
    v[i] = parseInt(parts[i], 10) || 0;
  }
  return v;
}

// dateAfter returns the date that is n days from today in "YYYYMMDD" format.
function dateAfter(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() + days);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${year}${month}${day}`;
}

async function ask(rl: readline.Interface, prompt: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => resolve(answer));
  });
}

async function main() {
  // Skip the first two entries: the runtime binary and the script path.
  const args = process.argv.slice(2);

  let mathID = "";
  let customKey = "";
  let expireDate = "";

  if (args.length === 0) {
    // Interactive mode
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    mathID = (await ask(rl, "Math ID (xxxx-xxxxx-xxxxx): ")).trim();
    customKey = (
      await ask(rl, "Activation Key (leave blank to generate one, format xxxx-xxxx-aaaaaa): ")
    ).trim();
    expireDate = (
      await ask(rl, "Expiry Date (YYYYMMDD, default 999 days from now): ")
    ).trim();

    rl.close();
  } else if (args.length === 1) {
    mathID = args[0];
  } else {
    mathID = args[0];
    customKey = args[1];
  }

  const mp = newMathPass(mathID, "14.1.0", customKey);
  generatePassword(mp, "800001", expireDate);

  console.log(`Activation Key: ${mp.activationKey}`);
  console.log(`Password: ${mp.password}`);
}

main().catch(console.error);
