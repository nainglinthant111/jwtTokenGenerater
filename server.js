const express = require('express');
const { CompactEncrypt, importJWK, JWKECKey } = require('jose');
const { randomBytes } = require('crypto');
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

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
