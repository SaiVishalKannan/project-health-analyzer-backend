const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const app = express();
const PORT = process.env.PORT || 5174;

app.use(cors());
app.use(bodyParser.json());

// Auth endpoints
const adminModule = require('./admin');
app.use('/api/auth', require('./auth'));
app.use('/api/admin', adminModule.router);

// Dummy AI logic (replace with real NLP/AI integration as needed)
function analyzeUpdate(text) {
  // Very basic NLP logic for demo (replace with real AI model)
  let sentiment = 'Neutral';
  let risk_level = 'Medium';
  let key_concerns = [];

  const lower = text.toLowerCase();
  if (/delay|late|behind|slip/.test(lower)) {
    risk_level = 'High';
    key_concerns.push('Delayed delivery');
  }
  if (/blocker|stuck|issue|problem/.test(lower)) {
    risk_level = 'High';
    key_concerns.push('Blockers present');
  }
  if (/resource|shortage|lack/.test(lower)) {
    risk_level = 'High';
    key_concerns.push('Resource shortage');
  }
  if (/happy|motivated|excited|good/.test(lower)) {
    sentiment = 'Positive';
  } else if (/stress|unhappy|demotivated|bad|frustrated/.test(lower)) {
    sentiment = 'Negative';
    key_concerns.push('Low team morale');
  }
  if (key_concerns.length === 0) key_concerns.push('No major concerns detected');

  return { sentiment, risk_level, key_concerns };
}

// API endpoint
app.post('/api/analyze', (req, res) => {
  const { text, user_id, email } = req.body;
  if (!text) return res.status(400).json({ error: 'No text provided' });
  const result = analyzeUpdate(text);
  // Audit log: analysis submission
  if (user_id && email) {
    adminModule.logAudit(user_id, email, 'Submitted analysis');
  }
  res.json(result);
});

app.listen(PORT, () => {
  console.log(`Project Health Analyzer backend running on http://localhost:${PORT}`);
});
