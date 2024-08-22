const express = require('express');
const { CompactEncrypt, importJWK, compactDecrypt } = require('jose');
const { randomBytes } = require('crypto');
const crypto = require('crypto');
const { log } = require('console');
require('dotenv').config();

const app = express();
const port = 3000;

async function generateToken(secretKey,jsonPayload) {
    const key = await importJWK({
        kty: 'oct',
        k: secretKey,
        alg: 'A128KW',
        use: 'enc'
    });

    const jwe = await new CompactEncrypt(Buffer.from(JSON.stringify(jsonPayload)))
        .setProtectedHeader({ alg: 'A128KW', enc: 'A128CBC-HS256' })
        .encrypt(key);
    return jwe;
}

async function getJsonDataFromToken(token, secretKey) {
    try {
        const key = await importJWK({
            kty: 'oct',
            k: secretKey,
            alg: 'A128KW',
            use: 'enc'
        });
         const { plaintext } = await compactDecrypt(token, key);
         const decryptedString = Buffer.from(plaintext).toString('utf-8');
         return JSON.parse(decryptedString);
    } catch (error) {
        console.error('Error during decryption:', error);
        throw error;
    }
}

function generateSecretKey() {
    return crypto.randomBytes(16).toString('base64'); // 128-bit key
}

app.use(express.json());
app.get('/',async(req,res)=>{
    res.status(200).json({
        "message":"Server is Ok!"
    })
});

app.post('/generate-token', async (req, res) => {
    try {
        const secretKey = req.headers['x-secret-key'];
        if(secretKey){
            const jsonPayload = req.body;
            const token = await generateToken(secretKey,jsonPayload); 
            console.log("Token Ok!");
            res.status(200).json({
                token: token
            });
        }else{
            res.status(404).send('SecretKey key is error');
        }
    } catch (error) {
        console.error('Error generating token:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/get-json', async (req, res) => {
    try {
        const tokenData = req.body;
        const token = tokenData.token;
        const secretKey = req.headers['x-secret-key'];
        console.log(secretKey,tokenData.token);
        
        if (!token || !secretKey) {
            return res.status(404).json({ error: 'Missing token or security key in headers' });
        }
        const jsonData = await getJsonDataFromToken(token, secretKey);
        res.json({ data: jsonData });
    } catch (error) {
        console.error('Error getting data from token:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/create-key', (req, res) => {
    const secretKey = generateSecretKey();
    console.log("Secret-key generate Successfully!")
    res.status(200).json({ secretKey });
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
