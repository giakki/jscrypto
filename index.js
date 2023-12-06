import fs from "node:fs";
import https from "node:https";
import crypto from "node:crypto";
import express from "express";

/** @type {https.ServerOptions} */
const options = {
    pfx: fs.readFileSync(process.env.JSCRYPTO_P12),
};

const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 4096,
});

const app = express();
app.use(express.static("public"));
app.use(express.json());
app.get("/.well-known/jwk.json", (_, res) => {
    res.json(publicKey.export({ format: "jwk" }));
});
app.post("/", (req, res) => {
    const encrypted = Buffer.from(req.body.encrypted, "base64");
    const decrypted = crypto
        .privateDecrypt(
            {
                key: privateKey,
                oaepHash: "sha256",
            },
            encrypted
        )
        .toString("utf-8");

    res.json({ decrypted });
});

https.createServer(options, app).listen(5173);
