const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const axios = require('axios');

dotenv.config();

const app = express();

// ✅ Enable CORS for your frontend (adjust if deploying from another domain)
app.use(cors({ origin: 'https://gregarious-maamoul-62e3c3.netlify.app' }));
app.use(bodyParser.json());

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_CALLBACK_URL = process.env.PAYSTACK_CALLBACK_URL || 'https://gregarious-maamoul-62e3c3.netlify.app/payment-success';

if (!PAYSTACK_SECRET_KEY) {
  console.error('❌ Paystack Secret Key is missing.');
  process.exit(1);
}

console.log('✅ Callback URL in use:', PAYSTACK_CALLBACK_URL);

// ✅ Home route
app.get('/', (req, res) => {
  res.send('🌸 Welcome to the Leye FlowerShop Backend!');
});
// Payment Initialization
app.post('/api/initialize-payment', async (req, res) => {
  const { email, amount, shippingDetails } = req.body;

  // Ensure that email and amount are provided
  if (!email || !amount) {
    return res.status(400).json({ message: 'Email and amount are required' });
  }

  try {
    const amountInNaira = amount; // Assuming amount is in NGN (₦)

    // Ensure amount doesn't exceed Paystack's limit (500,000 NGN)
    if (amountInNaira > 500000) {
      return res.status(400).json({
        message: 'Amount exceeds allowed limit. Reduce the total purchase amount.',
      });
    }

    // Convert amount to Kobo (Paystack uses Kobo, where 1 Naira = 100 Kobo)
    const amountInKobo = Math.round(amountInNaira * 100);

    const paymentData = {
      email,
      amount: amountInKobo,  // Amount is in Kobo (1 Naira = 100 Kobo)
      currency: 'NGN',       // Currency is Naira (NGN)
      callback_url: PAYSTACK_CALLBACK_URL, // Define a callback URL
      metadata: {
        shipping_details: shippingDetails,
        user_email: email,  // For better tracking
      },
    };

    // Make request to Paystack to initialize the payment
    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      paymentData,
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,  // Paystack Secret Key
        },
      }
    );

    console.log('Paystack API Response:', response.data); // Log full response from Paystack

    // Check if the authorization_url exists and send it back
    const { authorization_url } = response.data.data;
    if (authorization_url) {
      console.log('Authorization URL:', authorization_url);  // Log the authorization URL for debugging
      res.json({ authorization_url });  // Send the authorization URL back to the frontend
    } else {
      res.status(500).json({ message: 'Failed to retrieve authorization URL from Paystack' });
    }
  } catch (error) {
    console.error('❌ Error initializing payment:', error.response?.data || error.message);
    res.status(500).json({ message: 'Payment initialization failed' });
  }
});


module.exports = app;
