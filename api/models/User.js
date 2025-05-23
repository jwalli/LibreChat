const mongoose = require('mongoose');
const { userSchema } = require('@librechat/data-schemas');

const User = mongoose.model('User', userSchema);

userSchema.add({
  provider: { type: String }, // z.B. 'bitrix'
  providerUserId: { type: String }, // Bitrix User-ID als String
});

module.exports = User;
