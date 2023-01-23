const assert = require('assert');
const expect = require('chai').expect;
const path = require("path");
const fs = require("fs");
const sanitizerChecker = require('../build/Release/sanitizerchecker.node');
const inputFolder = __dirname + '/../../input3';

fs.readdir(inputFolder, (err, files) => {
  const errors = ['None', 'InfiniteRegex', 'NotImplemented', 'Other', 'UnsupportedFunction', 'MalformedDepgraph', 'UrlInReplaceString', 'UrlInReplaceString', 'LargeEncodeAttrChain', 'LargeEncodeTextChain', 'RegExpParseError', 'MonaException', 'InvalidArgument', 'InfiniteLength'];
    files.forEach(file => {
      const absolutePath = path.resolve(inputFolder, file);
      const content = fs.readFileSync(absolutePath, {encoding: 'utf8'});
        describe(file, function () {
            it('should call parseDepString on the content without an error', function () {
                expect(errors).to.include(sanitizerChecker.parseDepString(content, "x"));
            });
        });
    });
  });
  