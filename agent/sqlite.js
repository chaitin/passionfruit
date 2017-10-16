function quote(table) {
  return `"${table.replace(/"/g, '')}"`
}

class Database {
  constructor(filename) {
    this.db = SqliteDatabase.open(filename)
  }

  tables() {
    const statement = this.prepare('SELECT tbl_name FROM sqlite_master WHERE type="table" and tbl_name <> "sqlite_sequence"')
    return this.all(statement).map(row => row[0])
  }

  columns(table) {
    // I know it's an injection, but since this tool allows you query arbitary sql,
    // leave this alone or help me commit some code to escape the table name

    const statement = this.prepare(`PRAGMA table_info(${quote(table)})`)
    return this.all(statement)
  }

  all(statement) {
    const result = []
    let row
    /* eslint no-cond-assign: 0 */
    while ((row = statement.step()) !== null)
      result.push(row)

    return result
  }

  prepare(sql, args = []) {
    const statement = this.db.prepare(sql)
    for (let i = 0; i < args.length; i++) {
      const index = i + 1
      const arg = args[i]
      if (typeof arg === 'number')
        if (Math.floor(arg) === arg)
          statement.bindInteger(index, arg)
        else
          statement.bindFloat(index, arg)
      else if (arg === null || typeof arg === 'undefined')
        statement.bindNull(index)
      else if (arg instanceof ArrayBuffer)
        statement.bindBlob(index, arg)
      else
        statement.bindText(index)
    }
    return statement
  }

  close() {
    return this.db.close()
  }
}

function data({ path, table }) {
  const db = new Database(path)
  const sql = `select * from ${quote(table)} limit 500`
  const result = {
    header: db.columns(table),
    data: db.all(db.prepare(sql)),
  }
  db.close()
  return result
}

function query({ path, sql }) {
  const db = new Database(path)
  const statement = db.prepare(sql)
  const result = db.all(statement)
  db.close()
  return result
}

function tables(path) {
  const db = new Database(path)
  const list = db.tables()
  db.close()
  return list
}

module.exports = {
  tables,
  query,

  Database,
  data,
}
