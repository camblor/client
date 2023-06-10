extern crate sha2;
extern crate digest;

use sha2::Sha256;
use sha2::Digest;
use std::fmt;
use std::rc::Rc;
use std::cell::RefCell;

#[derive(Clone)]
pub struct HashProof {
    pub hash: String,
    pub direction: Direction,
}

#[derive(Clone)]
#[derive(Debug)]
pub enum Direction {
    Left,
    Right,
}

#[derive(Debug)]
struct Node {
    data: Option<String>,
    hash: String,
    parent: Option<Rc<RefCell<Node>>>,
    left: Option<Rc<RefCell<Node>>>,
    right: Option<Rc<RefCell<Node>>>,
}

impl Node {
    fn new(data: String) -> Rc<RefCell<Node>> {
        let mut hasher = Sha256::new();
        hasher.update(&data);

        Rc::new(RefCell::new(Node {
            data: Some(data),
            hash: format!("{:x}", hasher.finalize()),
            parent: None,
            left: None,
            right: None,
        }))
    }

    fn combine(left: Rc<RefCell<Node>>, right: Rc<RefCell<Node>>) -> Rc<RefCell<Node>> {
        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", left.borrow().hash, right.borrow().hash));
    
        let node = Rc::new(RefCell::new(Node {
            data: None,
            hash: format!("{:x}", hasher.finalize()),
            parent: None,
            left: Some(left.clone()),
            right: Some(right.clone()),
        }));
    
        left.borrow_mut().parent = Some(node.clone());
        right.borrow_mut().parent = Some(node.clone());
    
        node
    }
}

struct MerkleTree {
    root: Option<Rc<RefCell<Node>>>,
}

impl MerkleTree {
    

    fn from_data(data: Vec<String>) -> MerkleTree {
        let mut nodes: Vec<_> = data.into_iter().map(Node::new).collect();

        while nodes.len() > 1 {
            nodes = nodes.chunks(2).map(|chunk| {
                match chunk {
                    [left, right] => Node::combine(left.clone(), right.clone()),
                    [left] => Node::combine(left.clone(), Node::new("".to_string())),
                    _ => unreachable!()
                }
            }).collect();
        }

        MerkleTree { root: nodes.into_iter().next() }
    }

    fn get_root_hash(&self) -> Option<String> {
        match &self.root {
            Some(node) => Some(node.borrow().hash.clone()),
            None => None,
        }
    }

    fn next_node(node: Rc<RefCell<Node>>) -> Option<Rc<RefCell<Node>>> {
        let node_borrow = node.borrow();
        if let Some(left) = &node_borrow.left {
            Some(left.clone())
        } else if let Some(right) = &node_borrow.right {
            Some(right.clone())
        } else {
            None
        }
    }

    pub fn find_data_node(&self, data: &str) -> Option<Rc<RefCell<Node>>> {
        let data_hash = format!("{:x}", Sha256::digest(data.as_bytes()));
        let mut current_level = vec![self.root.clone()];
        while !current_level.is_empty() {
            let mut next_level = Vec::new();
            for node_opt in &current_level {
                if let Some(node) = node_opt {
                    if node.borrow().hash == data_hash {
                        return Some(node.clone());
                    } else {
                        next_level.push(node.borrow().left.clone());
                        next_level.push(node.borrow().right.clone());
                    }
                }
            }
            current_level = next_level;
        }
        None
    }
    
    
    pub fn generate_proof(&self, target_data: &str) -> Option<(String, Vec<HashProof>)> {
        let node = self.find_data_node(target_data)?;
    
        let mut proof = Vec::new();
        let leaf_hash = node.borrow().hash.clone();
        let mut current_node = node;
    
        while let Some(parent_ref) = {
            let current_node_borrow = current_node.borrow();
            current_node_borrow.parent.clone()
        } {
            let parent_borrow = parent_ref.borrow();
            let left = parent_borrow.left.as_ref().unwrap().clone();
            let right = parent_borrow.right.as_ref().unwrap().clone();
    
            if Rc::ptr_eq(&left, &current_node) {
                proof.push(HashProof {
                    hash: right.borrow().hash.clone(),
                    direction: Direction::Right,
                });
            } else {
                proof.push(HashProof {
                    hash: left.borrow().hash.clone(),
                    direction: Direction::Left,
                });
            }
            
            current_node = parent_ref.clone();
        }
    
        Some((leaf_hash, proof))
    }

    pub fn verify_proof(&self, data: &str, proof: &[HashProof], root_hash: &str) -> bool {
        // Compute the hash of the data
        let mut current_hash = format!("{:x}", Sha256::digest(data.as_bytes()));
    
        // Traverse the proof from leaf to root
        let mut i = 1;
        for hash_proof in proof.iter() {
            let mut hasher = Sha256::new();
            if matches!(hash_proof.direction, Direction::Left) {
                hasher.update(format!("{}{}", hash_proof.hash, current_hash));
            } else {
                hasher.update(format!("{}{}", current_hash, hash_proof.hash));
            }
    
            current_hash = format!("{:x}", hasher.finalize());
            i += 1;
        }
    
        // If the computed root hash is equal to the actual root hash, the proof is valid
        current_hash == *root_hash
    }
    
    
    
    
    
    
    
    
}

impl fmt::Display for MerkleTree {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut current_level = vec![self.root.as_ref().cloned()];
        let mut next_level = Vec::new();
        while !current_level.is_empty() {
            for node_opt in &current_level {
                match node_opt {
                    Some(node) => {
                        let node_ref = node.borrow();
                        write!(f, "{} ", node_ref.hash)?;
                        next_level.push(node_ref.left.as_ref().cloned());
                        next_level.push(node_ref.right.as_ref().cloned());
                    },
                    None => {
                        let _ = write!(f, "# ");
                    },
                }
            }
            writeln!(f)?;
            current_level = next_level.drain(..).collect();
        }
        Ok(())
    }
}



fn main() {
    let data = vec![
        "Hello".to_string(),
        "Merkle".to_string(),
        "Tree".to_string(),
        "Test".to_string(),
    ];

    let merkle_tree = MerkleTree::from_data(data);

    println!("Merkle Tree:");
    println!("{}", merkle_tree);

    let root_hash = match merkle_tree.get_root_hash() {
        Some(hash) => hash,
        None => String::from("No root hash found"),
    };
    println!("Root Hash: {}", root_hash);

    let target_data = "Merkle";
    let (target_hash, proof) = merkle_tree.generate_proof(target_data).unwrap_or((String::new(), Vec::new()));

    println!("Proof for \"{}\":", target_data);
    for hash_proof in &proof {
        println!("Hash: {}, Direction: {:?}", hash_proof.hash, hash_proof.direction);
    }

    let is_valid = merkle_tree.verify_proof(target_data, &proof, &root_hash);
    println!("Is the proof valid? {}", is_valid);
}



