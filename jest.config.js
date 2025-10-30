module.exports = {
  transform: {
    '^.+\\.js$': 'babel-jest',
  },
  transformIgnorePatterns: [
    '/node_modules/(?!axios-cookiejar-support|http-cookie-agent).+\\.js$',
  ]
};
