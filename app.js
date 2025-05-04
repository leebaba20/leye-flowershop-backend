const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const axios = require('axios');

dotenv.config();

const app = express();

// ✅ Enable CORS for your frontend
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

// ✅ Initialize Payment Route
app.post('/api/initialize-payment', async (req, res) => {
  const { email, amount, shippingDetails, cartItems } = req.body;

  if (!email || !amount) {
    return res.status(400).json({ message: 'Email and amount are required' });
  }

  try {
    if (amount > 500000) {
      return res.status(400).json({
        message: 'Amount exceeds allowed limit. Reduce the total purchase amount.',
      });
    }

    const amountInKobo = Math.round(amount * 100);

    const paymentData = {
      email,
      amount: amountInKobo,
      currency: 'NGN',
      callback_url: PAYSTACK_CALLBACK_URL,
      metadata: {
        shipping_details: shippingDetails,
        cartItems: cartItems || [],
        user_email: email,
      },
    };

    const response = await axios.post(
      'https://api.paystack.co/transaction/initialize',
      paymentData,
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    const { authorization_url } = response.data.data;
    if (authorization_url) {
      res.json({ authorization_url });
    } else {
      res.status(500).json({ message: 'Failed to retrieve authorization URL from Paystack' });
    }
  } catch (error) {
    console.error('❌ Error initializing payment:', error.response?.data || error.message);
    res.status(500).json({ message: 'Payment initialization failed' });
  }
});

// ✅ Verify Payment Route
app.post('/api/verify-payment', async (req, res) => {
  const { reference } = req.body;

  if (!reference) {
    return res.status(400).json({ message: 'Reference is required for verification' });
  }

  try {
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        },
      }
    );

    const data = response.data;

    if (data.status && data.data.status === 'success') {
      const order = {
        Shipping: data.data.metadata?.shipping_details || {},
        cartItems: data.data.metadata?.cartItems || [],
        email: data.data.customer?.email || '',
        reference: data.data.reference,
      };

      return res.status(200).json({ message: 'Payment successful', data: order });
    } else {
      return res.status(400).json({ message: 'Payment not successful' });
    }
  } catch (error) {
    console.error('❌ Error verifying payment:', error.response?.data || error.message);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

module.exports = app;
