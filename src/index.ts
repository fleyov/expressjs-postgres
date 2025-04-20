import bodyParser from "body-parser"
import express from "express"
import pg from "pg"

const { Pool } = pg
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
})

const app = express()
const port = process.env.PORT || 3333

app.use(bodyParser.json())

//AUTH ENDPOINT
app.post('/auth', async (req, res) => {
  const { key, hwid } = req.body

  //check secret from header'
  const authHeader = req.headers['authorization']
  if (!authHeader || authHeader !== process.env.API_SECRET) {
    return res.status(403).send('unauthorized')
  }

  if (!key || !hwid) return res.status(400).send('missing data')

  try {
    const result = await pool.query(
      'SELECT * FROM users WHERE license_key = $1',
      [key]
    )

    if (result.rows.length === 0) return res.status(401).send('invalid key')

    const user = result.rows[0]

    if (user.banned) return res.status(403).send('banned')
    if (user.hwid !== hwid) return res.status(401).send('invalid hwid')

    res.send('auth success')
  } catch (err) {
    console.error(err)
    res.status(500).send('server error')
  }
})

//test-check
app.get("/", async (_, res) => {
  const { rows } = await pool.query("SELECT NOW()")
  res.send(`API running. Time from DB: ${rows[0].now}`)
})

app.listen(port, () => {
  console.log(`auth server running on port ${port}`)
})
