# Node Library Generator

**Requirements**

- Python v3.x
- make
- node
- A proper C/C++ compiler toolchain, like GCC
- node-gyp globally installed:
`npm install -g node-gyp`

**Steps**

1. Build the sanitizer checker using `bash build.sh`
2. In `nodelib` install the required node modules using `npm install`.
3. Configure node-gyp: `node-gyp configure`.
4. Build the .node file using: `node-gyp build`. At the end of this step, a file called *sanitizerchecker.node* is generated in *nodelib/build/Release*.
5. Test the generated library by running `node index.js`.

