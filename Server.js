// server.js
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const paystack = require('paystack-node');

// Load environment variables from .env file
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json()); // Built-in JSON parsing (no need for body-parser)

// Initialize Paystack with your secret key
const paystackSecretKey = process.env.PAYSTACK_SECRET_KEY;
const paystackInstance = new paystack(paystackSecretKey);

// Payment Initialization Route
app.post('/api/initialize-payment', async (req, res) => {
  const { email, amount } = req.body;

  try {
    // Initialize the Paystack payment with USD currency
    const paymentData = {
      email: email,
      amount: amount * 100, // Convert to kobo (100 kobo = 1 Naira, 1 USD = 100 cents)
      currency: 'USD', // Set currency to USD (can be changed to another currency)
      callback_url: process.env.PAYSTACK_CALLBACK_URL, // URL for handling payment verification
    };

    const response = await paystackInstance.transaction.initialize(paymentData);
    const authorization_url = response.data.authorization_url;

    // Send the Paystack URL to the frontend for redirection
    res.json({ authorization_url });
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
      // Handle successful payment
      res.status(200).json({ message: 'Payment successful', data: transactionData });
    } else {
      // Handle failed payment
      res.status(400).json({ message: 'Payment failed' });
    }
  } catch (error) {
    console.error('Error verifying payment:', error);
    res.status(500).json({ message: 'Payment verification failed' });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
