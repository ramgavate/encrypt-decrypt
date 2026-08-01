function getKeyLength() {
  return Number(document.getElementById("ivLength").value);
}

const SUPPORTED_LENGTHS = [16, 31, 64];
const FORMAT_MAGIC = [0x45, 0x44, 0x31]; // "ED1"

function handleIvLengthChange() {
  const input = document.getElementById("key");
  const maxLength = getKeyLength();

  input.maxLength = maxLength;

  if (input.value.length > maxLength) {
    input.value = input.value.slice(0, maxLength);
  }

  handleKeyInput(input);
}

function showToast(message) {

  const toast = document.getElementById("toast");

  toast.innerText = message;

  toast.classList.add("show");

  setTimeout(() => {
    toast.classList.remove("show");
  }, 2000);

}

function encryptData() {

  const key = document.getElementById("key").value;

  const input = document.getElementById("inputData").value;

  const expectedLength = getKeyLength();

  if (key.length !== expectedLength) {
    showToast(`Key must be ${expectedLength} characters`);
    return;
  }

  if (!input) {
    showToast("Input data is empty");
    return;
  }

  try {

    const encrypted = encryptAES(input, key);

    document.getElementById("outputData").value = encrypted;

    showToast("Encryption successful");

  } catch (err) {

    console.error(err);

    showToast("Encryption failed");

  }

}

function decryptData() {

  const key = document.getElementById("key").value;

  const input = document.getElementById("inputData").value.trim();

  const expectedLength = getKeyLength();

  if (key.length !== expectedLength) {
    showToast(`Key must be ${expectedLength} characters`);
    return;
  }

  if (!input) {
    showToast("Input data is empty");
    return;
  }

  try {

    const decrypted = decryptAES(input, key);

    if (!decrypted) {
      showToast("Invalid key or encrypted data");
      return;
    }

    let output = decrypted;

    try {

      const parsed = JSON.parse(decrypted);

      output = JSON.stringify(parsed, null, 2);

      showToast("Decryption successful (JSON formatted)");

    } catch {

      showToast("Decryption successful");

    }

    document.getElementById("outputData").value = output;

  } catch (err) {

    console.error(err);

    showToast(err.message || "Decryption failed");

  }

}

function handleKeyInput(input) {

  const maxLength = getKeyLength();

  if (input.value.length > maxLength) {
    input.value = input.value.slice(0, maxLength);
  }

  const counter = document.getElementById("keyCounter");

  counter.innerText = `${input.value.length} / ${maxLength}`;

  validateKey(input.value, maxLength, input);

}

function validateKey(key, maxLength, input) {

  const error = document.getElementById("keyError");

  const encryptBtn = document.getElementById("encryptBtn");

  const decryptBtn = document.getElementById("decryptBtn");

  if (key.length !== maxLength) {

    error.innerText = `Key must be ${maxLength} characters`;

    encryptBtn.disabled = true;

    decryptBtn.disabled = true;

    input.classList.add("invalid");

    return false;

  }

  error.innerText = "";

  input.classList.remove("invalid");

  encryptBtn.disabled = false;

  decryptBtn.disabled = false;

  return true;

}

function encryptAES(plainText, encryptionKey) {

  const key = CryptoJS.SHA256(encryptionKey);

  const ivLength = getKeyLength();

  const ivMaterial = CryptoJS.lib.WordArray.random(ivLength);

  // AES-CBC always requires a 16-byte IV. For the selectable 31/64-byte
  // material, derive a deterministic 16-byte working IV without discarding
  // the extra entropy. The full material is stored with the ciphertext.
  const ivHash = CryptoJS.SHA256(CryptoJS.enc.Hex.stringify(ivMaterial));

  const iv = CryptoJS.lib.WordArray.create(ivHash.words.slice(0, 4), 16);

  const encrypted = CryptoJS.AES.encrypt(

    plainText,

    key,

    {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    }

  );

  const header = bytesToWordArray([...FORMAT_MAGIC, ivLength]);

  const combined = header.concat(ivMaterial).concat(encrypted.ciphertext);

  return CryptoJS.enc.Base64.stringify(combined);

}

function decryptAES(encryptedData, encryptionKey) {

  const key = CryptoJS.SHA256(encryptionKey);

  const decoded = CryptoJS.enc.Base64.parse(encryptedData);

  const decodedBytes = wordArrayToBytes(decoded);

  const hasVersionedHeader = FORMAT_MAGIC.every(
    (value, index) => decodedBytes[index] === value
  );

  let ivLength = 16;

  let ciphertextOffset = 16;

  let iv;

  if (hasVersionedHeader) {

    ivLength = decodedBytes[3];

    if (!SUPPORTED_LENGTHS.includes(ivLength)) {
      throw new Error("Unsupported IV length in encrypted data");
    }

    if (decodedBytes.length <= 4 + ivLength) {
      throw new Error("Encrypted data is incomplete");
    }

    const selectedLength = getKeyLength();

    if (encryptionKey.length !== ivLength || selectedLength !== ivLength) {
      throw new Error(`Select ${ivLength} bytes and use a ${ivLength}-character key`);
    }

    const ivMaterial = bytesToWordArray(decodedBytes.slice(4, 4 + ivLength));

    const ivHash = CryptoJS.SHA256(CryptoJS.enc.Hex.stringify(ivMaterial));

    iv = CryptoJS.lib.WordArray.create(ivHash.words.slice(0, 4), 16);

    ciphertextOffset = 4 + ivLength;

  } else {

    // Backward compatibility with ciphertexts created by the original tool,
    // which stored a raw 16-byte IV without a version header.
    if (encryptionKey.length !== 16) {
      throw new Error("Legacy encrypted data requires a 16-character key");
    }

    iv = bytesToWordArray(decodedBytes.slice(0, 16));

  }

  const ciphertext = bytesToWordArray(decodedBytes.slice(ciphertextOffset));

  const decrypted = CryptoJS.AES.decrypt(

    { ciphertext: ciphertext },

    key,

    {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    }

  );

  return decrypted.toString(CryptoJS.enc.Utf8);

}

function wordArrayToBytes(wordArray) {

  const bytes = [];

  for (let index = 0; index < wordArray.sigBytes; index += 1) {
    bytes.push(
      (wordArray.words[index >>> 2] >>> (24 - (index % 4) * 8)) & 0xff
    );
  }

  return bytes;

}

function bytesToWordArray(bytes) {

  const words = [];

  bytes.forEach((byte, index) => {
    words[index >>> 2] = (words[index >>> 2] || 0) |
      (byte << (24 - (index % 4) * 8));
  });

  return CryptoJS.lib.WordArray.create(words, bytes.length);

}

function copyText(id) {

  const text = document.getElementById(id);

  navigator.clipboard.writeText(text.value);

  showToast("Copied to clipboard!");

}

function formatJSON() {

  const textarea = document.getElementById("inputData");

  try {

    const parsed = JSON.parse(textarea.value);

    textarea.value = JSON.stringify(parsed, null, 2);

    showToast("JSON formatted");

  } catch {

    showToast("Invalid JSON");

  }

}

function formatOutputJSON() {

  const textarea = document.getElementById("outputData");

  try {

    const parsed = JSON.parse(textarea.value);

    textarea.value = JSON.stringify(parsed, null, 2);

    showToast("Output JSON formatted");

  } catch {

    showToast("Output is not valid JSON");

  }

}

document.getElementById("ivLength").addEventListener(
  "change",
  handleIvLengthChange
);

handleIvLengthChange();
