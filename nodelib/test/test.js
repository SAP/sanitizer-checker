const assert = require('assert');
const path = require("path");
const fs = require("fs");
const sanitizerChecker = require('../build/Release/sanitizerchecker.node');
const inputFolder = __dirname + '/../../input';

fs.readdir(inputFolder, (err, files) => {
    files.forEach(file => {
      const absolutePath = path.resolve(inputFolder, file);
      const content = fs.readFileSync(absolutePath, {encoding: 'utf8'});
        describe(file, function () {
            it('should call parseDepString on the content without an error', function () {
                assert.equal(sanitizerChecker.parseDepString(content, "x"), '');
            });
        });
    });
  });
  