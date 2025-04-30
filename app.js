// app.js
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const paystack = require('paystack-node');

dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const paystackInstance = new paystack(process.env.PAYSTACK_SECRET_KEY);

// Root Route
app.get('/', (req, res) => {
  res.send('Welcome to the Leye FlowerShop Backend!');
});

// Payment Initialization Route
app.post('/api/initialize-payment', async (req, res) => {
  const { email, amount } = req.body;
  try {
    const paymentData = {
      email,
      amount: parseInt(amount),
      currency: 'USD',
      callback_url: process.env.PAYSTACK_CALLBACK_URL || 'https://yourfrontend.com/payment-success',
    };
    const response = await paystackInstance.transaction.initialize(paymentData);
    res.json({ authorization_url: response.data.authorization_url });
  } catch (error) {
    console.error('Error initializing payment:', error);
    res.status(500).json({ message: 'Payment initialization failed' });
  }
});

// Payment Verification Route
app.post('/api/verify-payment', async (req, res) => {
  const { reference } = req.body;
  try {
    const response = await paystackInstance.transaction.verify(reference);
    const transactionData = response.data;
    if (transactionData.status === 'success') {
      res.status(200).json({ message: 'Payment successful', data: transactionData });
    } else {
      res.status(400).json({ message: 'Payment failed' });
    }
  } catch (error) {
    console.error('Error verifying payment:', error);
    res.status(500).json({ message: 'Payment verification failed' });
  }
});

module.exports = app;
