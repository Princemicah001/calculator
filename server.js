// server.js
const express = require('express');
const path = require('path');

const app = express();
const PORT = 3000;

const LOGO_DEV_TOKEN = 'pk_NElI-AhVS-qP7iOLicx2zg';

app.use(express.static(path.join(__dirname, 'public')));

// Route 1: Search for companies
app.get('/api/logos', async (req, res) => {
  const query = req.query.q?.trim();
  if (!query) return res.status(400).json({ error: 'Missing "q" parameter' });

  try {
    const url = `https://autocomplete.clearbit.com/v1/companies/suggest?query=${encodeURIComponent(query)}`;
    const r = await fetch(url);

    if (!r.ok) return res.status(r.status).json({ error: `Lookup failed (${r.status})` });

    const data = await r.json();

    const results = data.map(c => ({
      name: c.name,
      domain: c.domain,
      logo: `https://img.logo.dev/${c.domain}?token=${LOGO_DEV_TOKEN}&size=400`, // Higher res for zooming
      favicon: `https://www.google.com/s2/favicons?domain=${c.domain}&sz=128`
    }));

    res.json(results);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Route 2: Proxy to download images (fixes CORS download restrictions)
app.get('/api/download', async (req, res) => {
  const { url, name } = req.query;
  if (!url) return res.status(400).send('URL required');

  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error('Failed to fetch image');

    const arrayBuffer = await response.arrayBuffer();
    const contentType = response.headers.get('content-type') || 'image/png';

    // Get file extension from content-type (defaults to .png if not found)
    const ext = contentType.split('/')[1] || 'png';
    // Sanitize filename
    const safeName = (name || 'logo').replace(/[^a-z0-9]/gi, '_');
    const filename = `${safeName}.${ext}`;

    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', contentType);
    res.send(Buffer.from(arrayBuffer));
  } catch (err) {
    console.error('Download error:', err);
    res.status(500).send('Error downloading image');
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
});
