const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const axios = require('axios');

dotenv.config();

const app = express();

// Enable CORS for Netlify frontend
app.use(cors({ origin: 'https://gregarious-maamoul-62e3c3.netlify.app' }));
app.use(bodyParser.json());

const PAYSTACK_SECRET_KEY = process.env.PAYSTACK_SECRET_KEY;
if (!PAYSTACK_SECRET_KEY) {
  console.error('❌ Paystack Secret Key is missing.');
  process.exit(1);
}

app.get('/', (req, res) => {
  res.send('🌸 Welcome to the Leye FlowerShop Backend!');
});

// Helper to convert USD to NGN
const convertUSDToNGN = (usdAmount) => {
  const USD_TO_NGN_RATE = 100; // You can adjust this or fetch dynamically
  return usdAmount * USD_TO_NGN_RATE;
};

// Payment Initialization
app.post('/api/initialize-payment', async (req, res) => {
  const { email, amount, currency = 'USD', shippingDetails } = req.body;

  if (!email || !amount) {
    return res.status(400).json({ message: 'Email and amount are required' });
  }

  try {
    let amountInNaira;

    if (currency === 'USD') {
      amountInNaira = convertUSDToNGN(amount);
    } else if (currency === 'NGN') {
      amountInNaira = amount;
    } else {
      return res.status(400).json({ message: 'Unsupported currency' });
    }

    if (amountInNaira > 2000000) {
      return res.status(400).json({
        message: 'Amount exceeds allowed limit. Reduce the total purchase amount.',
      });
    }

    const amountInKobo = Math.round(amountInNaira * 100);

    const paymentData = {
      email,
      amount: amountInKobo,
      currency: 'NGN',
      callback_url: process.env.PAYSTACK_CALLBACK_URL || 'https://gregarious-maamoul-62e3c3.netlify.app/payment-success',
      metadata: { shipping_details: shippingDetails },
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
    res.json({ authorization_url });
  } catch (error) {
    console.error('❌ Error initializing payment:', error.response?.data || error.message);
    res.status(500).json({ message: 'Payment initialization failed' });
  }
});

// Payment Verification
app.post('/api/verify-payment', async (req, res) => {
  const { reference } = req.body;

  if (!reference) {
    return res.status(400).json({ message: 'Payment reference is required' });
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

    const transactionData = response.data.data;

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
