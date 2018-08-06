const fs = require('fs')
const path = require('path')
const { promisify } = require('util')

const { setUp } = require('../lib/db')

const exists = promisify(fs.exists)

async function main() {
  if (await exists(path.join(__dirname, '..', '.git')))
    process.env.NODE_ENV = 'development'

  try {
    await setUp()
    console.log('successfully created database')
  } catch (ex) {
    console.error('failed to initialize database', ex.stack)
    process.exit(-1)
  }
}

main()
