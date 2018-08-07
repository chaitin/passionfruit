module.exports = {
  port: parseInt(process.env.PORT, 10) || 31337,
  host: process.env.HOST || 'localhost',
}
