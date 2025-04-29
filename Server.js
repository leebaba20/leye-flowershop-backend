const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const paystack = require('paystack-node');
const bodyParser = require('body-parser');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());

const paystackInstance = new paystack(process.env.PAYSTACK_SECRET_KEY);

// Payment Initialization Route
app.post('/api/initialize-payment', async (req, res) => {
  const { email, amount } = req.body;

  try {
    const paymentData = {
      email,
      amount: parseInt(amount), // amount already in kobo (100 = $1)
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

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
