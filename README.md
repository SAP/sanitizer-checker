# SAP Repository Template

Default templates for SAP open source repositories, including LICENSE, .reuse/dep5, Code of Conduct, etc... All repositories on github.com/SAP will be created based on this template.

## To-Do

In case you are the maintainer of a new SAP open source project, these are the steps to do with the template files:

- Check if the default license (Apache 2.0) also applies to your project. A license change should only be required in exceptional cases. If this is the case, please change the [license file](LICENSE).
- Enter the correct metadata for the REUSE tool. See our [wiki page](https://wiki.wdf.sap.corp/wiki/display/ospodocs/Using+the+Reuse+Tool+of+FSFE+for+Copyright+and+License+Information) for details how to do it. You can find an initial .reuse/dep5 file to build on. Please replace the parts inside the single angle quotation marks < > by the specific information for your repository and be sure to run the REUSE tool to validate that the metadata is correct.
- Adjust the contribution guidelines (e.g. add coding style guidelines, pull request checklists, different license if needed etc.)
- Add information about your project to this README (name, description, requirements etc). Especially take care for the <your-project> placeholders - those ones need to be replaced with your project name. See the sections below the horizontal line and [our guidelines on our wiki page](https://wiki.wdf.sap.corp/wiki/display/ospodocs/Guidelines+for+README.md+file) what is required and recommended.
- Remove all content in this README above and including the horizontal line ;)

***

# Our new open source project

## About this project

*Insert a short description of your project here...*

## Requirements and Setup

*Insert a short description what is required to get your project running...*

# SemAttack: Generating Sanitizer Bypasses for Client-Side JavaScript

This repository contains source code for SemAttack, a framework which uses symbolic string analysis to evaluate the security of client-side JavaScript sanitizer functions.

## Introduction

This framework was used to perform a large scale analysis of sanitizer functions in the wild, as detailed in the paper **Hand Sanitizers in the Wild: A Large-scale Study of Custom JavaScript Sanitizer Functions** by [David Klein](https://www.tu-braunschweig.de/en/ias/staff/david-klein), [Thomas Barber](https://www.linkedin.com/in/thomas-barber-b3965551/), Souphiane Bensalim, [Ben Stock](https://people.cispa.io/ben.stock/) and [Martin Johns](https://www.tu-braunschweig.de/en/ias/staff/martin-johns). More information and additional supporting material can be found [here](https://github.com/ias-tubs/hand_sanitizer).

### Cite Us!

```bibtex
@inproceedings{KleBarBen+22,
  author = {David Klein and Thomas Barber and Souphiane Bensalim and Ben Stock and Martin Johns},
  title = {Hand Sanitizers in the Wild: A Large-scale Study of Custom JavaScript Sanitizer Functions},
  booktitle = {Proc. of the IEEE European Symposium on Security and Privacy},
  year = {2022},
  month = jun,
}
```

## Background

This code is build on a number of existing symbolic string analysis frameworks:

* [MONA](https://github.com/cs-au-dk/MONA) is a C implementation of finite-state automata. We use a fork of MONA, which is downloaded as part of the build process from [here](https://github.com/tmbrbr/MONA).
* [LibStranger](https://github.com/vlab-cs-ucsb/LibStranger) is an Automata-based string analysis library written in C. Our fork of the stranger library is found in the [stranger](stranger) subdirectory.
* [SemRep](https://github.com/vlab-cs-ucsb/SemRep) is a differential repair tool for sanitizer functions, which includes a C++ wrapper for stranger. We fork and enhance the C++ components in the [semattack](semattack) subdirectory.

This implementation provides the following additional functionality compared to the baseline components as follows.

### MONA

As described in this [commit](https://github.com/tmbrbr/MONA/commit/d6dbfbaeaa2b38abc439f014a795868bbf8e43cf), we enhanced the MONA library to enable execution of the library in parallel on multiple threads. This was necessary to process the large number of sanitizer functions found in our study. This involved:

* Extracting globally stored state objects when constructing DFAs into function arguments (e.g. DFABuilder)
* Adding appropriate error code propagation to functions instead of aborting program execution

### LibStranger

We made a number of enhancements to LibStranger to allow analysis of modern, client-side JavaScript functions, including:

* Modelling JavaScript replace semantics, in particular ```replace("string", "anotherString")```, which will only replace the first instance of a String in JavaScript.
* Implementation of built-in browser encoding functions, such as ```escape```, ```encodeURI```, etc.
* Approximations during backwards analysis for pre-image computation in cases where the DFA state exceeds the allowed limits set by MONA

### SemAttack

In SemAttack, we enhanced the C++ implementation of SemRep to construct a framework for large scale sanitizer analysis. This included:

* Reading in a directory containing dependency graphs, and queuing their analysis
* Parallel forward analysis execution for post-image computation
* Parallel backwards analysis for pre-image computation
* Multiple attack pattern specification for sanitizer classification. The configured attack patterns consist of typical characers which have semantic meaning in HTML (e.g. "<" or ">" characters)
* Construction of a context specific attack pattern based on the exploit generation in the metadata of the input dependency graphs. This was used to compute specific bypasses for data flows.

<<<<<<< HEAD
## Support, Feedback, Contributing

This project is open to feature requests/suggestions, bug reports etc. via [GitHub issues](https://github.com/SAP/<your-project>/issues). Contribution and feedback are encouraged and always welcome. For more information about how to contribute, the project structure, as well as additional contribution information, see our [Contribution Guidelines](CONTRIBUTING.md).

## Code of Conduct

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone. By participating in this project, you agree to abide by its [Code of Conduct](CODE_OF_CONDUCT.md) at all times.
=======
## Building

To build SemAttack, just run the build.sh script:

```bash
bash build.sh
```

This script will install all necessary prerequisites, clone a copy of our MONA fork, and run the necessary build commands. Sudo rights are required to install pacakges and build artifacts. The build script has been tested using Ubuntu 20.04.

### Docker build

If you are running something other than Ubuntu, or don't want to install additional packages locally, try building in a docker container:

```bash
docker build -t semattack .
```

## Input Files

To run the analysis, you first need some depedency graphs as inputs. A slimmed down and anonymized dataset of dependency graphs from our analysis can be found in the [input](input) directory. A description of the Dependency Graph format can be found [here](semattack#input-format-what-is-a-dependency-graph).

Our dependency graph dataset was generated by crawling the top 20,000 most popular websites and collecting dynamic taint flows using an instrumented [web browser](https://github.com/SAP/project-foxhound). The taint flows were converted into dependency graphs with additional information added related to the website, source and sink context and generated exploit payloads.

## Running SemAttack

After building, SemAttack can be run as follows:

```bash
semattack/src/multiattack --target input --output output --fieldname x
```

### Docker run

If you are using docker, the input and output directories have to be mounted into the container:

```bash
docker run -v /path/to/input:/work/depgraphs -v /path/to/output:/work/output semattack
```

The folder mapped to ``/work/depgraphs`` contains the input files and multiattack writes the results to the folder mapped onto ``/work/output``.

### Command line options

To get a list of command line flags, run:

```bash
semattack/src/multiattack --help
```

## Understanding the Output



## Other Tools

There are a few other tools included to help with the analysis:

### Single File Analysis

Instead of analysing a whole directly, to just analyse a single file:

```bash
semattack/src/semattack --target input/finding_1.dot --fieldname x
```

### Automatonify

This is a test program to convert a string or regular expression into a DFA. For example:

```bash
semattack/src/automatonify --string "/a+ab/" --output test.dot
```

will produce the following graphviz output:

```
digraph MONA_DFA {
 rankdir = LR;
 center = true;
 size = "700.5,1000.5";
 edge [fontname = Courier];
 node [height = .5, width = .5];
 node [shape = doublecircle]; 4;
 node [shape = circle]; 0; 2; 3;
 node [shape = box];
 init [shape = plaintext, label = ""];
 init -> 0;
 0 -> 2 [label=" a"];
 2 -> 3 [label=" a"];
 3 -> 3 [label=" a"];
 3 -> 4 [label=" b"];
}
```

Which you can render or view online, e.g. [here](https://dreampuf.github.io/GraphvizOnline/#digraph%20MONA_DFA%20%7B%0D%0A%20rankdir%20%3D%20LR%3B%0D%0A%20center%20%3D%20true%3B%0D%0A%20size%20%3D%20%22700.5%2C1000.5%22%3B%0D%0A%20edge%20%5Bfontname%20%3D%20Courier%5D%3B%0D%0A%20node%20%5Bheight%20%3D%20.5%2C%20width%20%3D%20.5%5D%3B%0D%0A%20node%20%5Bshape%20%3D%20doublecircle%5D%3B%204%3B%0D%0A%20node%20%5Bshape%20%3D%20circle%5D%3B%200%3B%202%3B%203%3B%0D%0A%20node%20%5Bshape%20%3D%20box%5D%3B%0D%0A%20init%20%5Bshape%20%3D%20plaintext%2C%20label%20%3D%20%22%22%5D%3B%0D%0A%20init%20-%3E%200%3B%0D%0A%200%20-%3E%202%20%5Blabel%3D%22%20a%22%5D%3B%0D%0A%202%20-%3E%203%20%5Blabel%3D%22%20a%22%5D%3B%0D%0A%203%20-%3E%203%20%5Blabel%3D%22%20a%22%5D%3B%0D%0A%203%20-%3E%204%20%5Blabel%3D%22%20b%22%5D%3B%0D%0A%7D%0D%0A).
>>>>>>> 676d42e... Adding build instructions

## Licensing

Copyright (20xx-)20xx SAP SE or an SAP affiliate company and <your-project> contributors. Please see our [LICENSE](LICENSE) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available [via the REUSE tool](https://api.reuse.software/info/github.com/SAP/<your-project>).
