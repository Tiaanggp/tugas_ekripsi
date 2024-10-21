const NodeRSA = require("node-rsa");

export default function handler(req, res) {
  if (req.method === "POST") {
    const { text, type } = req.body;
    const key = new NodeRSA({ b: 512 });

    if (type === "encrypt") {
      const encrypted = key.encrypt(text, "base64");
      res
        .status(200)
        .json({ result: encrypted, publicKey: key.exportKey("public") });
    } else if (type === "decrypt") {
      try {
        const decrypted = key.decrypt(text, "utf8");
        res.status(200).json({ result: decrypted });
      } catch (error) {
        res.status(400).json({ error: "Decryption failed" });
      }
    }
  } else {
    res.status(405).json({ error: "Method not allowed" });
  }
}
