require('dotenv').config();
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const app = express();

const stateStore = {};

// Log the environment variables for debugging
console.log('Client ID:', process.env.LINKEDIN_CLIENT_ID);
console.log('Client Secret:', process.env.LINKEDIN_CLIENT_SECRET);
console.log('Redirect URI:', process.env.REDIRECT_URI);

// Middleware function to log incoming requests
app.use((req, res, next) => {
    console.log(`Incoming request: ${req.method} ${req.url}`);
    next(); // Pass control to the next middleware/route handler
});

// Simple route
app.get('/', (req, res) => {
    res.send('Hello, Express Server!');
});

// Middleware function to validate access token
const validateAccessToken = async (req, res, next) => {
    const accessToken = req.query.accessToken; // Assuming accessToken is passed as a query parameter
    try {
        if (!accessToken) {
            return res.status(401).json({ error: 'Access token is required' });
        }

        const response = await axios.get('https://api.linkedin.com/v2/me', {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });

        if (response.data.id) {
            next();
        } else {
            return res.status(401).json({ error: 'Invalid access token' });
        }
    } catch (error) {
        console.error('Error validating access token:', error.message);
        return res.status(500).json({ error: 'Internal server error' });
    }
};

// Route to initiate LinkedIn OAuth flow
app.get('/auth/linkedin', (req, res) => {
    const clientId = process.env.LINKEDIN_CLIENT_ID;
    const redirectUri = process.env.REDIRECT_URI;
    const scope = 'openid profile email w_member_social';
    const state = crypto.randomBytes(20).toString('hex'); // Generate a random state parameter

    // Store the state parameter in memory
    stateStore[state] = true;

    const authorizationUrl = `https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=${clientId}&redirect_uri=${redirectUri}&scope=${scope}&state=${state}`;
    res.redirect(authorizationUrl);
});

// Route to handle LinkedIn OAuth callback
app.get('/auth/linkedin/callback', async (req, res) => {
    const authorizationCode = req.query.code;
    const state = req.query.state;
    const clientId = process.env.LINKEDIN_CLIENT_ID;
    const clientSecret = process.env.LINKEDIN_CLIENT_SECRET;
    const redirectUri = process.env.REDIRECT_URI;

    // Validate the state parameter
    if (!stateStore[state]) {
        return res.status(400).json({ error: 'Invalid state parameter' });
    }

    // Remove the state from the store
    delete stateStore[state];

    try {
        const response = await axios.post('https://www.linkedin.com/oauth/v2/accessToken', null, {
            params: {
                grant_type: 'authorization_code',
                code: authorizationCode,
                redirect_uri: redirectUri,
                client_id: clientId,
                client_secret: clientSecret
            },
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        });

        const accessToken = response.data.access_token;
        res.json({ access_token: accessToken });
    } catch (error) {
        console.error('Error exchanging authorization code for access token:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Route to fetch LinkedIn profile details using access token
app.get('/profile', validateAccessToken, async (req, res) => {
    const accessToken = req.query.accessToken; // Assuming accessToken is passed as a query parameter
    try {
        const response = await axios.get('https://api.linkedin.com/v2/me', {
            headers: {
                'Authorization': `Bearer ${accessToken}`
            }
        });
        const profile = response.data;
        res.json(profile);
    } catch (error) {
        console.error('Error fetching LinkedIn profile:', error.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Protected route using middleware for access token validation
app.get('/protected', validateAccessToken, (req, res) => {
    res.send('Access granted to protected route!');
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});
