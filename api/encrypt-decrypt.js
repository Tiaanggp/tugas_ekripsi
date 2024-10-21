const express = require("express");
const crypto = require("crypto");
const bodyParser = require("body-parser");

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.json());
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type");
  next();
});

// RSA Key Generation
let { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

// Request and Response types
class Request {
  constructor(text, type) {
    this.text = text;
    this.type = type;
  }
}

class Response {
  constructor(result, publicKey, error) {
    this.result = result;
    this.publicKey = publicKey;
    this.error = error;
  }
}

// Route Handler
app.post("/", (req, res) => {
  const { text, type } = req.body;

  if (type === "encrypt") {
    const buffer = Buffer.from(text);
    const encryptedText = crypto.publicEncrypt(publicKey, buffer);
    const base64Encrypted = encryptedText.toString("base64");
    const publicKeyBase64 = publicKey
      .export({ type: "spki", format: "der" })
      .toString("base64");
    res.json(new Response(base64Encrypted, publicKeyBase64, null));
  } else if (type === "decrypt") {
    try {
      const encryptedBuffer = Buffer.from(text, "base64");
      const decryptedText = crypto.privateDecrypt(privateKey, encryptedBuffer);
      res.json(new Response(decryptedText.toString(), null, null));
    } catch (error) {
      res.json(new Response(null, null, "Decryption failed"));
    }
  } else {
    res.status(400).json({ error: "Invalid operation type" });
  }
});

// Handle CORS preflight requests
app.options("/", (req, res) => {
  res.sendStatus(200);
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
