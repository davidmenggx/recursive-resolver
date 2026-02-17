import os

class TrieNode:
    def __init__(self, is_leaf: bool = False):
        self.children: dict[str, TrieNode] = {}
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
            
            matching_key = next((k for k in curr.children if k[0] == key[0]), None)

            if not matching_key: # add a new key
                curr.children[key] = TrieNode(is_leaf=True)
                return

            prefix = os.path.commonprefix([key, matching_key])
            key = key[len(prefix):]

            if prefix == matching_key: # full edge match => truncate and continue
                curr = curr.children[matching_key]
                continue
            
            else:
                intermediate_node = TrieNode()
                intermediate_node.children[matching_key[len(prefix):]] = curr.children[matching_key]

                del curr.children[matching_key]
                curr.children[prefix] = intermediate_node

                if not key:
                    intermediate_node.is_leaf = True
                else:
                    intermediate_node.children[key] = TrieNode(is_leaf=True)

                return

    def search(self, key: str):
        ...
    
    def delete(self, key: str) -> None:
        ...