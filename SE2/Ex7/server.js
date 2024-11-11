const express = require('express')

const app = express()
const port = 3001

// system variables where RP credentials are stored
const googleClient = {
    ID: process.env.CLIENT_ID,
    SECRET: process.env.CLIENT_SECRET
}

const dropboxClient = {
    KEY: process.env.APP_KEY,
    SECRET: process.env.APP_SECRET
}

require('./web-api')(app, googleClient, dropboxClient)

app.listen(port, (err) => {
    if (err) console.log('Something bad happened: ', err)
    else console.log(`Server is listening on ${port}...`)
})