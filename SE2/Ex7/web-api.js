'use strict'

const cookie_parser = require('cookie-parser')

const request = require('request')

const html_helper = require('./html_helper')

const crypto = require('crypto');
const hmac = crypto.createHmac('sha256', 'changeit')

module.exports = (app, googleClient, dropboxClient) => {
    const CLIENT_ID = googleClient.ID
    const CLIENT_SECRET = googleClient.SECRET

    const APP_KEY = dropboxClient.KEY
    const APP_SECRET = dropboxClient.SECRET

    const sessions = new Map()

    const table_headers = [
        { name: '', prop: 'copyToDropbox' },
        { name: 'File Name', prop: 'originalFilename' },
        { name: 'Type', prop: 'mimeType' }
    ]


    app.use(cookie_parser())

    app.get('/', (req, res) => {
        const ssid = req.cookies.SSID
        const session = sessions.get(ssid)
        if (session && session.googleToken && session.dropboxToken) // user logged with both services
            res.send(html_helper.generateHTML('Home',
                '<form action="drive/files">' +
                '<input type="submit" value="Check drive files"/>' +
                '</form>')
            )
        else
            res.send(html_helper.generateHTML('Home',
                '<form action="googlelogin">' +
                '<input type="submit" value="Login with Google"' + (session && session.googleToken ? ' disabled="disabled"' : '') + '/>' +
                '</form>' +
                '<form action="dropboxlogin">' +
                '<input type="submit" value="Login with Dropbox"' + (session && session.dropboxToken ? ' disabled="disabled"' : '') + '/>' +
                '</form>')
            )
    })

    // copy the file with the id from google drive to dropbox
    app.post('/copy/drive/:id/dropbox', (req, res, next) => {
        const ssid = req.cookies.SSID
        const session = sessions.get(ssid)
        if (session && session.googleToken && session.dropboxToken) { // user logged with both services
            const driveFileOptions = makeUriWithAuth('https://www.googleapis.com/drive/v2/files/' + req.params.id, session.googleToken)
            driveFileOptions.json = true

            request.get(driveFileOptions, (err, resp, fileMeta) => {
                if (err || resp.statusCode != 200) return next(new Error('Something went wrong'))
                const isGoogleDoc = fileMeta.mimeType.indexOf('google') >= 0
                const filename = isGoogleDoc ?
                    `${fileMeta.title}.pdf` :
                    (fileMeta.originalFilename ? fileMeta.originalFilename : `output.${fileMeta.fileExtension}`)
                const downloadUrl = isGoogleDoc ? fileMeta.exportLinks['application/pdf'] : fileMeta.downloadUrl

                const driveFileContentOptions = makeUriWithAuth(downloadUrl, session.googleToken)

                const dropboxUploadOptions = {
                    url: 'https://content.dropboxapi.com/2/files/upload',
                    headers: {
                        Authorization: 'Bearer ' + session.dropboxToken,
                        'Dropbox-API-Arg': dropboxApiArgs(filename),
                        'Content-Type': 'application/octet-stream'
                    }
                }
                request.get(driveFileContentOptions)
                    .on('response', res => delete res.headers['content-type']) // avoid override of content-type for post
                    .pipe(request.post(dropboxUploadOptions, (err, resp) => {
                        if (err || resp.statusCode != 200) next(new Error('Something went wrong'))
                    }))

                //send something to user
                res.send(html_helper.generateHTML('File Uploaded', `<p>File uploaded successfully to your Dropbox at \`/CopiedFromGoogleDrive/${filename}\`</p><br><a href="/" type="button">Back to home</a>`))
            })
        } else next(new Error('User not authenticated'))
    })

    // get all the files from client google drive
    app.get('/drive/files', (req, res, next) => {
        const ssid = req.cookies.SSID
        const session = sessions.get(ssid)
        if (session && session.googleToken && session.dropboxToken) { // user logged with both services
            const options = makeUriWithAuth('https://www.googleapis.com/drive/v2/files', session.googleToken)
            const nextPage = req.query.next
            if (nextPage) { //if user requested next page lets get next page
                options.qs = {
                    pageToken: nextPage
                }
            }
            options.json = true

            request.get(options, (err, resp, body) => {
                if (err || resp.statusCode != 200) return next(new Error('Something went wrong'))
                const table = html_helper.generateTable(body.items.filter(file => file.mimeType != 'application/vnd.google-apps.folder')
                    .map(file => {
                        file.copyToDropbox = `<form action="/copy/drive/${file.id}/dropbox" method="post">` +
                            '<input type="submit" value="Copy"/>' +
                            '</form>'
                        if (!file.originalFilename) file.originalFilename = file.title
                        return file
                    })
                    , table_headers)
                const btns = body.nextPageToken ? `<br><a href="?next=${body.nextPageToken}" type="button">Next Page</a>` : ''
                res.send(html_helper.generateHTML('Drive Files',
                    `${table}
                <br>
                <a href="?" type="button">First Page</a>
                ${btns}`))
            })
        } else next(new Error('User not authenticated'))
    })

    // endpoint for google login
    app.get('/googlelogin', (req, res, next) => {
        res.redirect(
            // authorization endpoint
            'https://accounts.google.com/o/oauth2/v2/auth?'
            // client id
            + 'client_id=' + CLIENT_ID + '&'
            // scope "openid email"
            + 'scope=https://www.googleapis.com/auth/drive.readonly&'
            // responde_type for "authorization code grant"
            + 'response_type=code&'
            // redirect uri used to register RP
            + 'redirect_uri=http://localhost:3001/googlecallback')
    })

    // endpoit for dropbox login
    app.get('/dropboxlogin', (req, res, next) => {
        res.redirect(
            // authorization endpoint
            'https://www.dropbox.com/oauth2/authorize?'
            // client id
            + 'client_id=' + APP_KEY + '&'
            // responde_type for "authorization code grant"
            + 'response_type=code&'
            // redirect uri used to register RP
            + 'redirect_uri=http://localhost:3001/dropboxcallback')
    })

    // endpoint for dropbox callback after client login
    app.get('/dropboxcallback', (req, res, next) => {
        const options = {
            url: 'https://api.dropboxapi.com/oauth2/token',
            json: true,
            // body parameters
            form: {
                code: req.query.code,
                client_id: APP_KEY,
                client_secret: APP_SECRET,
                redirect_uri: 'http://localhost:3001/dropboxcallback',
                grant_type: 'authorization_code'
            }
        }

        request.post(options, (err, resp, body) => {
            if (err || resp.statusCode != 200) return next(new Error('Something went wrong'))

            const ssid = req.cookies.SSID

            if (ssid) { // if cookie
                const session = sessions.get(ssid)
                if (session) // check if there is an entrance in the map
                    session.dropboxToken = body.access_token
                else        // otherwise set an entrance with the cookie ssid
                    sessions.set(ssid, { dropboxToken: body.access_token })
            } else { // if no cookie lets generate one and save it
                const cookieSSID = generateSSID(req.ip)
                const session = { dropboxToken: body.access_token }
                sessions.set(cookieSSID, session)
                res.setHeader('Set-Cookie', ['SSID=' + cookieSSID]);
            }
            res.send(html_helper.generateHTML('Dropbox callback', '<p>Logged with Dropbox</p><br><a href="/" type="button">Back to home</a>'))
        });
    })

    // endpoint for google callback after client login
    app.get('/googlecallback', (req, res, next) => {
        const options = {
            url: 'https://www.googleapis.com/oauth2/v4/token',
            json: true,
            // body parameters
            form: {
                code: req.query.code,
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                redirect_uri: 'http://localhost:3001/googlecallback',
                grant_type: 'authorization_code'
            }
        }

        request.post(options, (err, resp, body) => {
            if (err || resp.statusCode != 200) return next(new Error('Something went wrong'))

            const ssid = req.cookies.SSID

            if (ssid) { // if cookie
                const session = sessions.get(ssid)
                if (session) // check if there is an entrance in the map
                    session.googleToken = body.access_token
                else        // otherwise set an entrance with the cookie ssid
                    sessions.set(ssid, { googleToken: body.access_token })
            } else { // if no cookie lets generate one and save it
                const cookieSSID = generateSSID(req.ip)
                const session = { googleToken: body.access_token }
                sessions.set(cookieSSID, session)
                res.setHeader('Set-Cookie', ['SSID=' + cookieSSID]);
            }
            res.send(html_helper.generateHTML('Google callback', '<p>Logged with Google</p><br><a href="/" type="button">Back to home</a>'))
        });
    })

    // error endpoint
    app.use((err, _, res, __) => {
        if (err) res.send(html_helper.generateHTML('Error', `<p>${err}</p><br><a href="/" type="button">Back to home</a>`))
        else res.status(404).send('<h1> 404 not found</h1>')
    })
}

function makeUriWithAuth(url, access_token) {
    const options = {
        uri: url,
        headers: {
            Authorization: 'Bearer ' + access_token
        }
    }
    return options
}

function dropboxApiArgs(filename) {
    return JSON.stringify({
        path: '/CopiedFromGoogleDrive/' + filename,
        mode: 'add',
        autorename: true
    })
}

function generateSSID(ip) {
    const h = hmac.digest(ip)
    return Buffer.from(h).toString('base64');
}