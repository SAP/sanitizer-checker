# Notes for using SemRep

## Building the dependency graph

- Nodes have to be named *n<id>*, if they are named e.g., *node<id>*, SemRep breaks.
- Concat nodes are written like:
```dot
n20 [shape=ellipse, label="."];
```
with two input children.
