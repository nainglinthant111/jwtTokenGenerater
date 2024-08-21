const express = require('express');
const { CompactEncrypt, importJWK, JWKECKey } = require('jose');
const { randomBytes } = require('crypto');
const { log } = require('console');
require('dotenv').config();

const app = express();
const port = 3000;

//(Base64-encoded)
const secretKey = 'u5e1DZB5+/7blHgN4lPIRg==';
// const secretKey = process.env.SECRET_KEY;

async function generateToken(jsonPayload) {
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
        const jsonPayload = req.body;
        const token = await generateToken(jsonPayload); 
        console.log(token);
        res.status(200).json({
            token: token
        });
    } catch (error) {
        console.error('Error generating token:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
