
class Database {
  constructor(filename) {
    this.db = SqliteDatabase.open(filename)
  }

  tables() {
    let statement = this.prepare('SELECT tbl_name FROM sqlite_master WHERE type="table"')
    return this.all(statement)
  }

  columns(table) {
    // I know it's an injection, but since this tool allows you query arbitary sql,
    // leave this alone or help me commit some code to escape the table name
    console.log(`PRAGMA table_info({table})`)
    let statement = this.prepare(`PRAGMA table_info(${table})`)
    return this.all(statement)
  }

  all(statement) {
    let result = [], row
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


function queryTable(filename, table) {
  let db = new Database(filename)
  let result = {
    header: db.columns(),
    data: db.query()
  }
  db.close()
}

function query(filename, sql) {
  let db = new Database(filename)
  let statement = db.prepare(sql)
  let result = db.all(statement)
  db.close()
  return result
}

function tables(filename) {
  let db = new Database(filename)
  let tables = db.tables()
  db.close()
  return tables
}

module.exports = {
  // todo: design the api?
  Database,
  queryTable
}