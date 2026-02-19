from __future__ import annotations

import os
from typing import NamedTuple

class NodeEdge(NamedTuple):
    edge: str
    node: TrieNode

class TrieNode:
    def __init__(self, is_leaf: bool = False):
        self.children: dict[str, NodeEdge] = {} # Maps first character : (full edge string, node object)
        self.is_leaf: bool = is_leaf

class RadixTrie:
    def __init__(self):
        self.root = TrieNode()
    
    def insert(self, key: str) -> None:
        curr = self.root
        while True:
            if not key:
                curr.is_leaf = True
                return
            
            match = curr.children.get(key[0])

            if not match: # add a new key
                curr.children[key[0]] = NodeEdge(key, TrieNode(is_leaf=True))
                return
            
            matching_edge = match.edge
            matching_node = match.node

            prefix = os.path.commonprefix([key, matching_edge])
            key = key[len(prefix):]

            if prefix == matching_edge: # full edge match => truncate and continue
                curr = curr.children[prefix[0]].node
                continue
            
            else:
                intermediate_node = TrieNode()
                intermediate_node.children[matching_edge[len(prefix):][0]] = NodeEdge(matching_edge[len(prefix):], matching_node)

                del curr.children[matching_edge[0]]
                curr.children[prefix[0]] = NodeEdge(prefix, intermediate_node)

                if not key:
                    intermediate_node.is_leaf = True
                else:
                    intermediate_node.children[key[0]] = NodeEdge(key, TrieNode(is_leaf=True))

                return

    def search(self, key: str) -> bool:
        curr = self.root
        while key:
            if key[0] not in curr.children:
                return False
            
            prefix = os.path.commonprefix([key, curr.children[key[0]].edge])

            if curr.children[key[0]].edge != prefix:
                return False
            
            curr = curr.children[key[0]].node
            key = key[len(prefix):]
        
        return curr.is_leaf
    
    def delete(self, key: str) -> None:
        if not self.search(key):
            return
        
        traversal_history = [] # stack to store previously visited nodes for merging

        curr = self.root
        while key:
            prefix = os.path.commonprefix([key, curr.children[key[0]].edge]) # maybe refactor this so its shorter since I don't need to calculate the entire prefix
            
            curr = curr.children[key[0]].node
            key = key[len(prefix):]

if __name__ == '__main__':
    tree = RadixTrie()

    tree.insert("test")
    tree.insert("apple")

    print(tree.search("test"))
    print(tree.search("apple"))
    print(tree.search("unknown"))

    tree.insert("teamwork")

    print(tree.search("team"))