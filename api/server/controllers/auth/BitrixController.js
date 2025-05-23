const axios = require('axios');
const User = require('~/models/User');
const crypto = require('crypto');

exports.startOAuth = async (req, res) => {
  const bitrixDomain = process.env.BITRIX_DOMAIN;
  const clientId = process.env.BITRIX_CLIENT_ID;
  const redirectUri = `${req.protocol}://${req.get('host')}/api/auth/bitrix/callback`;
  const url = `${bitrixDomain}/oauth/authorize/?client_id=${clientId}&response_type=code&redirect_uri=${encodeURIComponent(redirectUri)}`;
  res.redirect(url);
};

exports.handleCallback = async (req, res) => {
  try {
    const { code } = req.query;
    if (!code) return res.redirect('/?error=bitrix_no_code');

    const bitrixDomain = process.env.BITRIX_DOMAIN;
    const clientId = process.env.BITRIX_CLIENT_ID;
    const clientSecret = process.env.BITRIX_CLIENT_SECRET;
    const redirectUri = `${req.protocol}://${req.get('host')}/api/auth/bitrix/callback`;

    // Token holen
    const tokenRes = await axios.get(
      `${bitrixDomain}/oauth/token/?client_id=${clientId}&client_secret=${clientSecret}&grant_type=authorization_code&code=${code}&redirect_uri=${encodeURIComponent(redirectUri)}`
    );
    const { access_token } = tokenRes.data;
    if (!access_token) return res.redirect('/?error=bitrix_no_token');

    // User holen
    const userRes = await axios.get(`${bitrixDomain}/rest/user.current?auth=${access_token}`);
    const userData = userRes.data.result;
    if (!userData || !userData.ID) return res.redirect('/?error=bitrix_no_user');

    // User anlegen oder updaten
    let user = await User.findOne({ provider: 'bitrix', providerUserId: userData.ID.toString() });
    if (!user) {
      user = new User({
        provider: 'bitrix',
        providerUserId: userData.ID.toString(),
        username: `bitrix_${userData.ID}`,
        email: userData.EMAIL || `bitrix_${userData.ID}@example.com`,
        name: `${userData.NAME} ${userData.LAST_NAME}`.trim(),
        password: crypto.randomBytes(24).toString('hex'),
        passwordVersion: 1,
      });
      await user.save();
    }

    req.login(user, (err) => {
      if (err) return res.redirect('/?error=bitrix_login');
      res.redirect('/');
    });
  } catch (e) {
    console.error('[Bitrix OAuth]', e);
    res.redirect('/?error=bitrix_oauth');
  }
};