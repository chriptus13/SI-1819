'use strict'

module.exports = {
    generateTable: function (values, headers) {
        const table = '<table class="table table-dark"><tr>'
        const val = headers
            .map(hdr => `<th>${hdr.name}</th>`)
            .reduce((prev, curr) => prev + curr, table) + '</tr>'

        return values
            .map(v => headers.map(hdr => `<td>${v[hdr.prop]}</td>`).reduce((prev, curr) => prev + curr, '<tr>') + '</tr>')
            .reduce((prev, curr) => prev + curr, val) + '</table>'
    },
    generateHTML: function (pageTitle, body) {
        return `<head>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
        <title>${pageTitle}</title>
        </head>
        <body>
        ${body}
        </body>`
    }
}