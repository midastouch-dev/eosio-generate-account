let express = require('express');
let cookieParser = require('cookie-parser');
let bodyParser = require('body-parser');
let apiTest = require('./routes/api_test');

let app = express();
require('dotenv').config();

app.get('/', function (req, res) {
    res.send('Server is running');
})

app.use(bodyParser.json({limit: '50mb'}));
app.use(bodyParser.urlencoded({limit: '50mb', extended: true}));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

app.use('/api/test', apiTest);

module.exports = app;
