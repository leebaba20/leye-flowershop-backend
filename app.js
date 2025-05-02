const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const axios = require('axios');

dotenv.config();

const app = express();

// Enable CORS for your frontend (Updated with new frontend URL)
app.use(cors({ origin: 'https://gregarious-maamoul-62e3c3.netlify.app' }));
app.use(bodyParser.json());

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
const PAYSTACK_CALLBACK_URL = process.env.PAYSTACK_CALLBACK_URL || 'https://gregarious-maamoul-62e3c3.netlify.app/payment-success';

if (!PAYSTACK_SECRET_KEY) {
  console.error('❌ Paystack Secret Key is missing.');
  process.exit(1);
}

if (!PAYSTACK_CALLBACK_URL) {
  console.error('❌ PAYSTACK_CALLBACK_URL is missing. Using fallback URL.');
}

console.log('Callback URL:', PAYSTACK_CALLBACK_URL); // Log the callback URL for debugging

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
    const amountInNaira = amount; // The frontend already sends this in Naira (₦)

    // Ensure amount doesn't exceed the Paystack limit (500,000 NGN)
    if (amountInNaira > 500000) {
      return res.status(400).json({
        message: 'Amount exceeds allowed limit. Reduce the total purchase amount.',
      });
    }

    // Convert amount to Kobo (Paystack uses Kobo, where 1 Naira = 100 Kobo)
    const amountInKobo = Math.round(amountInNaira * 100);

    const paymentData = {
      email,
      amount: amountInKobo,  // Amount is now in Kobo
      currency: 'NGN',       // Currency is Naira (NGN)
      callback_url: PAYSTACK_CALLBACK_URL,
      metadata: {
        shipping_details: shippingDetails,
        user_email: email,  // Use the email from frontend for better tracking
      },
    };

    // Make request to Paystack to initialize the payment
    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      paymentData,
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    // Extract authorization URL from Paystack's response and send it back to the frontend
    const { authorization_url } = response.data.data;
    res.json({ authorization_url });
  } catch (error) {
    console.error('❌ Error initializing payment:', error.response?.data || error.message);
    res.status(500).json({ message: 'Payment initialization failed' });
  }
});

// Payment Verification
app.post('/api/verify-payment', async (req, res) => {
  const { reference } = req.body;

  // Ensure that reference is provided
  if (!reference) {
    return res.status(400).json({ message: 'Payment reference is required' });
  }

  try {
    // Verify the payment using the reference from Paystack
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    // Get transaction data from Paystack's response
    const transactionData = response.data.data;

    // Check if the payment was successful
    if (transactionData.status === 'success') {
      res.status(200).json({ message: 'Payment successful', data: transactionData });
    } else {
      res.status(400).json({ message: 'Payment failed', data: transactionData });
    }
  } catch (error) {
    console.error('❌ Error verifying payment:', error.response?.data || error.message);
    res.status(500).json({ message: 'Payment verification failed' });
  }
});

module.exports = app;
