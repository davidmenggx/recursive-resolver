import os

class TrieNode:
    def __init__(self, is_leaf: bool = False):
        self.children: dict[str, tuple[str, TrieNode]] = {}
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
                curr.children[key[0]] = (key, TrieNode(is_leaf=True))
                return
            
            matching_edge, matching_node = match

            prefix = os.path.commonprefix([key, matching_edge])
            key = key[len(prefix):]

            if prefix == matching_edge: # full edge match => truncate and continue
                curr = curr.children[prefix[0]][1]
                continue
            
            else:
                intermediate_node = TrieNode()
                intermediate_node.children[matching_edge[len(prefix):][0]] = (matching_edge[len(prefix):], matching_node)

                del curr.children[matching_edge[0]]
                curr.children[prefix[0]] = (prefix, intermediate_node)

                if not key:
                    intermediate_node.is_leaf = True
                else:
                    intermediate_node.children[key[0]] = (key, TrieNode(is_leaf=True))

                return

    def search(self, key: str):
        ...
    
    def delete(self, key: str) -> None:
        ...