const express = require("express");
const { CompactEncrypt, importJWK, compactDecrypt } = require("jose");
const { randomBytes } = require("crypto");
const crypto = require("crypto");
require("dotenv").config();
const cors = require("cors");

const app = express();
app.use(cors({ origin: "*" }));
const port = 3000;

async function generateToken(secretKey, jsonPayload) {
    const key = await importJWK({
        kty: "oct",
        k: secretKey,
        alg: "A128KW",
        use: "enc",
    });

    const jwe = await new CompactEncrypt(
        Buffer.from(JSON.stringify(jsonPayload))
    )
        .setProtectedHeader({ alg: "A128KW", enc: "A128CBC-HS256" })
        .encrypt(key);
    return jwe;
}

// In-memory store to back 64-character opaque tokens
const tokenStore = new Map();

async function getJsonDataFromToken(token, secretKey) {
    try {
        const key = await importJWK({
            kty: "oct",
            k: secretKey,
            alg: "A128KW",
            use: "enc",
        });
        const { plaintext } = await compactDecrypt(token, key);
        const decryptedString = Buffer.from(plaintext).toString("utf-8");
        return JSON.parse(decryptedString);
    } catch (error) {
        console.error("Error during decryption:", error);
        throw error;
    }
}

function generateSecretKey() {
    return crypto.randomBytes(16).toString("base64"); // 128-bit key
}

app.use(express.json());
app.get("/", async (req, res) => {
    res.status(200).json({
        message: "Server is Ok!",
    });
});

app.post("/generate-token", async (req, res) => {
    try {
        const secretKey = req.headers["x-secret-key"];
        if (secretKey) {
            const jsonPayload = req.body;
            // 64-character token: 32 random bytes hex-encoded
            const token = crypto.randomBytes(32).toString("hex");
            tokenStore.set(token, { payload: jsonPayload, secretKey });
            res.status(200).json({ token });
        } else {
            res.status(404).send("SecretKey key is error");
        }
    } catch (error) {
        console.error("Error generating token:", error);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/get-json", async (req, res) => {
    try {
        const token = req.query.token;
        const secretKey = req.headers["x-secret-key"];

        if (!token || !secretKey) {
            return res
                .status(404)
                .json({ error: "Missing token or security key in headers" });
        }
        const record = tokenStore.get(token);
        if (!record) {
            return res.status(404).json({ error: "Token not found" });
        }
        if (record.secretKey !== secretKey) {
            return res
                .status(403)
                .json({ error: "Invalid secret key for token" });
        }
        res.json({ data: record.payload });
    } catch (error) {
        console.error("Error getting data from token:", error);
        res.status(500).send("Internal Server Error");
    }
});

app.get("/create-key", (req, res) => {
    const secretKey = generateSecretKey();
    res.status(200).json({ secretKey });
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
