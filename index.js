const dotenv = require('dotenv').config();
const express = require('express');
const app = express();
const crypto = require('crypto');
const cookie = require('cookie');
const nonce = require('nonce')();
const querystring = require('querystring');
const request = require('request-promise');

const apiKey = process.env.SHOPIFY_API_KEY;
const apiSecret = process.env.SHOPIFY_API_SECRET;
const scopes = 'read_products,read_locations';
const forwardingAddress = "https://fc2fd18b.ngrok.io"; // Replace this with your HTTPS Forwarding address

//https://fc2fd18b.ngrok.io/shopify?shop=trusted-login-plus.myshopify.com
app.get('/', (req, res) => {
    res.send('Hello World!');
});

/**
 * The install route expects a shop URL parameter, 
 * which it uses to redirect the merchant to the 
 * Shopify app authorization prompt where they can 
 * choose to accept or reject the installation request.
 */
app.get('/shopify', (req, res) => {
    console.log('====shopify===');
    const shop = req.query.shop;
    if (shop) {
        const state = nonce();
        const redirectUri = forwardingAddress + '/shopify/callback';
        const installUrl = 'https://' + shop +
            '/admin/oauth/authorize?client_id=' + apiKey +
            '&scope=' + scopes +
            '&state=' + state +
            '&redirect_uri=' + redirectUri;

        res.cookie('state', state);


        console.log('shop : ' + shop);
        console.log('state : ' + state);
        console.log('scopes : ' + scopes);
        console.log('forwardingAddress : ' + forwardingAddress);
        console.log('redirect_uri : ' + redirectUri);
        console.log('installUrl : ' + installUrl);


        res.redirect(installUrl);
    } else {
        return res.status(400).send('Missing shop parameter. Please add ?shop=your-development-shop.myshopify.com to your request');
    }
});

/**
 * After a user accepts the install request, 
 * Shopify sends them to the redirect_uri that 
 * you specified in the previous step. This address 
 * needs match the URL that you entered under 
 * Whitelisted redirection URL(s) in the Partner Dashboard. 
 * The request from Shopify includes a code parameter 
 * that needs to be exchanged for a permanent access token.
 */
app.get('/shopify/callback', (req, res) => {
    const { shop, hmac, code, state } = req.query;
    const stateCookie = cookie.parse(req.headers.cookie).state;

    if (state !== stateCookie) {
        return res.status(403).send('Request origin cannot be verified');
    }

    if (shop && hmac && code) {
        // DONE: Validate request is from Shopify
        const map = Object.assign({}, req.query);
        delete map['signature'];
        delete map['hmac'];
        const message = querystring.stringify(map);
        const providedHmac = Buffer.from(hmac, 'utf-8');
        const generatedHash = Buffer.from(
            crypto
                .createHmac('sha256', apiSecret)
                .update(message)
                .digest('hex'),
            'utf-8'
        );

        console.log('====shopify/callback===');
        console.log('shop : ' + shop);
        console.log('hmac : ' + hmac);
        console.log('code : ' + code);
        console.log('state : ' + state);
        console.log('stateCookie : ' + stateCookie);
        console.log('map : ' + JSON.stringify(map));
        console.log('message : ' + JSON.stringify(message));

        let hashEquals = false;

        try {
            hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac)
        } catch (e) {
            hashEquals = false;
        };

        if (!hashEquals) {
            return res.status(400).send('HMAC validation failed');
        }

        console.log('====shopify/callback===to exchange the provided code parameter for a permanent access_token====');
        // DONE: Exchange temporary code for a permanent access token
        const accessTokenRequestUrl = 'https://' + shop + '/admin/oauth/access_token';
        const accessTokenPayload = {
            client_id: apiKey,
            client_secret: apiSecret,
            code,
        };

        console.log('accessTokenRequestUrl : ' + accessTokenRequestUrl);
        console.log('accessTokenPayload : ' + JSON.stringify(accessTokenPayload));
        request.post(accessTokenRequestUrl, { json: accessTokenPayload })
            .then((accessTokenResponse) => {
                const accessToken = accessTokenResponse.access_token;
                console.log('accessToken : ' + accessToken);

                console.log('====shopify/callback===to use the access token to make an API call to the shop endpoint====');
                // DONE: Use access token to make API call to 'shop' endpoint
                const shopRequestUrl = 'https://' + shop + '/admin/shop.json';
                const shopRequestHeaders = {
                    'X-Shopify-Access-Token': accessToken,
                };

                console.log('shopRequestUrl : ' + shopRequestUrl);
                console.log('shopRequestHeaders : ' + JSON.stringify(shopRequestHeaders));

                request.get(shopRequestUrl, { headers: shopRequestHeaders })
                    .then((shopResponse) => {
                        console.log('shopResponse : \n' + shopResponse);
                        res.status(200).end(shopResponse);
                    })
                    .catch((error) => {
                        res.status(error.statusCode).send(error.error.error_description);
                    });
            })
            .catch((error) => {
                res.status(error.statusCode).send(error.error.error_description);
            });

    } else {
        res.status(400).send('Required parameters missing');
    }
});

app.listen(3000, () => {
    console.log('Example app listening on port 3000!');
});