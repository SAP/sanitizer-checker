const path = require("path");
const fs = require("fs");
const chalk = require('chalk');
const sanitizerChecker = require('../build/Release/sanitizerchecker.node');

const inputFolder = '../../input/';

fs.readdir(inputFolder, (err, files) => {
  files.forEach(file => {
    const absolutePath = path.resolve(inputFolder, file);
    const content = fs.readFileSync(absolutePath, {encoding: 'utf8'});
    try {
        console.log(chalk.bgGreen('analyzing ' + file));
        const result = sanitizerChecker.parseDepString(content, "x");
        
        fs.writeFile('./output/' + file, result, (err) => {
            if (err) {
                console.log(chalk.red('%s not successful'), file);
            } else {
                console.log(chalk.green('%s successful'), file);
            }
        });
    } catch(err) {
        console.log(chalk.red('%s not successful'), file);
    }
  });
});
