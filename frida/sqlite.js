class Database {
  constructor(filename) {
    this.db = SqliteDatabase.open(filename)
  }

  tables() {
    let statement = this.prepare(
      'SELECT tbl_name FROM sqlite_master WHERE type="table" and tbl_name <> "sqlite_sequence"')
    return this.all(statement).map(row => row[0])
  }

  columns(table) {
    // I know it's an injection, but since this tool allows you query arbitary sql,
    // leave this alone or help me commit some code to escape the table name

    let statement = this.prepare(`PRAGMA table_info(${table})`)
    return this.all(statement)
  }

  all(statement) {
    let result = [],
      row
    while ((row = statement.step()) !== null) {
      result.push(row)
    }
    return result
  }

  prepare(sql, args) {
    args = args || []
    let statement = this.db.prepare(sql)
    for (let i = 0; i < args.length; i++) {
      let index = i + 1
      let arg = args[i]
      if (typeof arg == 'number') {
        if (Math.floor(arg) === arg)
          statement.bindInteger(index, arg)
        else
          statement.bindFloat(index, arg)
      } else if (arg === null || typeof arg === 'undefined') {
        statement.bindNull(index)
      } else if (arg instanceof ArrayBuffer) {
        statement.bindBlob(index, arg)
      } else {
        statement.bindText(index)
      }
    }
    return statement
  }

  close() {
    return this.db.close()
  }
}


function data({ path, table }) {
  let db = new Database(path)
  let sql = `select * from ${table} limit 500`
  let result = {
    header: db.columns(table),
    data: db.all(db.prepare(sql))
  }
  db.close()
  return result
}

function query({ path, sql }) {
  let db = new Database(path)
  let statement = db.prepare(sql)
  let result = db.all(statement)
  db.close()
  return result
}

function tables(path) {
  let db = new Database(path)
  let tables = db.tables()
  db.close()
  return tables
}

module.exports = {
  // todo: design the api?
  tables,
  query,

  Database,
  data
}