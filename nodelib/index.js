const sanitizerChecker = require('./build/Release/sanitizerchecker.node');

console.log(sanitizerChecker);

const test1 = "digraph cfg {\nn0 [shape=house, label=\"Input: x\"];\nn1 [shape=ellipse, label=\".\"];\nn2 [shape=box, label=\"Lit: &gt;\"];\nn3 [shape=ellipse, label=\".\"];\nn4 [shape=box, label=\"Lit: &lt;\"];\nn5 [shape=ellipse, label=\".\"];\nn6 [shape=box, label=\"Lit: &lt;\"];\nn7 [shape=ellipse, label=\"preg_replace\"];\nn8 [shape=box, label=\"RegExp: /[\\x00\\x22\\x26\\x27\\x3c\\x3e]/\"];\nn9 [shape=box, label=\"Lit: \"];\nn10 [shape=box, label=\"Var: x\"];\nn11 [shape=box, label=\"Var: x\"];\nn12 [shape=doubleoctagon, label=\"Return: x\"];\nn1 -> n0;\nn1 -> n2;\nn3 -> n1;\nn3 -> n4;\nn5 -> n3;\nn5 -> n6;\nn10 -> n5;\nn7 -> n8;\nn7 -> n9;\nn7 -> n10;\nn11 -> n7;\nn12 -> n11;\n}";

sanitizerChecker.parseDepString(test1, "x")