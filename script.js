function getKeyLength() {
  return 16;
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

    showToast("Decryption failed");

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

  const iv = CryptoJS.lib.WordArray.random(16);

  const encrypted = CryptoJS.AES.encrypt(

    plainText,

    key,

    {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    }

  );

  const combined = iv.concat(encrypted.ciphertext);

  return CryptoJS.enc.Base64.stringify(combined);

}

function decryptAES(encryptedData, encryptionKey) {

  const key = CryptoJS.SHA256(encryptionKey);

  const decoded = CryptoJS.enc.Base64.parse(encryptedData);

  const iv = CryptoJS.lib.WordArray.create(decoded.words.slice(0, 4), 16);

  const ciphertext = CryptoJS.lib.WordArray.create(

    decoded.words.slice(4),

    decoded.sigBytes - 16

  );

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