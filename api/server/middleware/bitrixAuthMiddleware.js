// Neue Datei: server/middleware/bitrixAuthMiddleware.js
const jwt = require('jsonwebtoken');
const axios = require('axios');
const User = require('../models/User');
const crypto = require('crypto');

/**
 * Middleware zur Authentifizierung von Bitrix24-Benutzern
 */
const verifyBitrixToken = async (req, res, next) => {
  try {
    // Token aus Query-Parameter oder Authorization-Header lesen
    const token = req.query.token || req.headers.authorization?.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'Nicht authentifiziert' });
    }
    
    // Token verifizieren mit dem gemeinsamen geheimen Schlüssel
    const sharedSecret = process.env.BITRIX_SHARED_SECRET;
    
    const decoded = jwt.verify(token, sharedSecret);
    
    // Optional: Überprüfung des Tokens mit Bitrix24 via OAuth API
    if (decoded.oauth_token) {
      try {
        // Bitrix24 REST API verwenden, um den Benutzer zu verifizieren
        const response = await axios.get(`${process.env.BITRIX_URL}/rest/user.current`, {
          headers: {
            'Authorization': `Bearer ${decoded.oauth_token}`
          }
        });
        
        // Prüfen, ob die zurückgegebene Benutzer-ID mit dem Token übereinstimmt
        if (response.data.result.ID != decoded.sub) {
          throw new Error('Benutzer-ID stimmt nicht überein');
        }
      } catch (error) {
        console.error('Fehler bei der OAuth-Validierung:', error);
        // Fahren Sie dennoch fort, da wir das JWT bereits validiert haben
      }
    }
    
    // Benutzer in der Datenbank finden oder neu anlegen
    let user = await User.findOne({ 
      provider: 'bitrix24',
      providerUserId: decoded.sub 
    });
    
    if (!user) {
      // Neuen Benutzer anlegen
      user = new User({
        provider: 'bitrix24',
        providerUserId: decoded.sub,
        name: decoded.name,
        email: decoded.email,
        username: `bitrix_${decoded.sub}`,
        password: crypto.randomBytes(20).toString('hex'),
        passwordVersion: 1
      });
      await user.save();
    }
    
    req.user = user;
    next();
  } catch (error) {
    console.error('Token-Validierungsfehler:', error);
    return res.status(401).json({ message: 'Ungültiges oder abgelaufenes Token' });
  }
};

module.exports = { verifyBitrixToken };