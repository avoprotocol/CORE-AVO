//! # Algoritmos DAG para AVO Protocol
//!
//! Implementación completa de algoritmos para el manejo del DAG (Directed Acyclic Graph)
//! incluyendo ordenamiento topológico, detección de ciclos y selección de tips.

use crate::error::{AvoError, AvoResult};
use crate::types::{Block, BlockId, Transaction, TransactionId};
use petgraph::algo::{is_cyclic_directed, toposort};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet, VecDeque};
use tracing::{debug, info, warn};

/// Nodo del DAG con metadatos
#[derive(Debug, Clone)]
pub struct DAGNode<T> {
    pub id: Vec<u8>,
    pub data: T,
    pub parents: Vec<Vec<u8>>,
    pub children: Vec<Vec<u8>>,
    pub height: u64,
    pub timestamp: u64,
    pub weight: f64,
}

/// Estructura principal del DAG
pub struct DAG<T> {
    /// Nodos indexados por ID
    nodes: HashMap<Vec<u8>, DAGNode<T>>,
    /// Grafo dirigido para algoritmos eficientes
    graph: DiGraph<Vec<u8>, f64>,
    /// Mapeo de IDs a índices del grafo
    id_to_node_index: HashMap<Vec<u8>, NodeIndex>,
    /// Tips del DAG (nodos sin hijos)
    tips: HashSet<Vec<u8>>,
    /// Raíces del DAG (nodos sin padres)
    roots: HashSet<Vec<u8>>,
}

impl<T: Clone> DAG<T> {
    /// Crear un nuevo DAG vacío
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            graph: DiGraph::new(),
            id_to_node_index: HashMap::new(),
            tips: HashSet::new(),
            roots: HashSet::new(),
        }
    }

    /// Agregar un nodo al DAG
    pub fn add_node(
        &mut self,
        id: Vec<u8>,
        data: T,
        parents: Vec<Vec<u8>>,
        timestamp: u64,
    ) -> AvoResult<()> {
        // Verificar que no existe ya
        if self.nodes.contains_key(&id) {
            return Err(AvoError::consensus(format!(
                "Node {:?} already exists in DAG",
                id
            )));
        }

        // Calcular altura basada en padres
        let height = if parents.is_empty() {
            0
        } else {
            parents
                .iter()
                .filter_map(|p| self.nodes.get(p))
                .map(|n| n.height)
                .max()
                .unwrap_or(0)
                + 1
        };

        // Crear nodo
        let node = DAGNode {
            id: id.clone(),
            data,
            parents: parents.clone(),
            children: Vec::new(),
            height,
            timestamp,
            weight: 1.0,
        };

        // Agregar al grafo
        let node_index = self.graph.add_node(id.clone());
        self.id_to_node_index.insert(id.clone(), node_index);

        // Conectar con padres
        for parent_id in &parents {
            if let Some(&parent_index) = self.id_to_node_index.get(parent_id) {
                self.graph.add_edge(parent_index, node_index, 1.0);

                // Actualizar hijos del padre
                if let Some(parent_node) = self.nodes.get_mut(parent_id) {
                    parent_node.children.push(id.clone());
                }

                // El padre ya no es un tip
                self.tips.remove(parent_id);
            } else {
                warn!("Parent node {:?} not found in DAG", parent_id);
            }
        }

        // Actualizar tips y roots
        if parents.is_empty() {
            self.roots.insert(id.clone());
        }

        // Nuevo nodo siempre es un tip inicialmente
        self.tips.insert(id.clone());

        // Agregar a nodos
        self.nodes.insert(id.clone(), node);

        // Verificar que no se introdujeron ciclos
        if is_cyclic_directed(&self.graph) {
            // Revertir cambios si hay ciclo
            self.nodes.remove(&id);
            self.graph.remove_node(node_index);
            self.id_to_node_index.remove(&id);
            self.tips.remove(&id);
            self.roots.remove(&id);

            return Err(AvoError::consensus(
                "Adding node would create a cycle in DAG",
            ));
        }

        debug!(
            "Added node to DAG - height: {}, parents: {}, tips: {}",
            height,
            parents.len(),
            self.tips.len()
        );

        Ok(())
    }

    /// Obtener ordenamiento topológico del DAG
    pub fn topological_sort(&self) -> AvoResult<Vec<Vec<u8>>> {
        match toposort(&self.graph, None) {
            Ok(sorted_indices) => {
                let sorted_ids: Vec<Vec<u8>> = sorted_indices
                    .into_iter()
                    .filter_map(|idx| self.graph.node_weight(idx).cloned())
                    .collect();

                Ok(sorted_ids)
            }
            Err(_) => Err(AvoError::consensus(
                "Cycle detected in DAG during topological sort",
            )),
        }
    }

    /// Verificar si el DAG contiene ciclos
    pub fn has_cycles(&self) -> bool {
        is_cyclic_directed(&self.graph)
    }

    /// Obtener todos los ancestros de un nodo
    pub fn get_ancestors(&self, id: &[u8]) -> HashSet<Vec<u8>> {
        let mut ancestors = HashSet::new();
        let mut queue = VecDeque::new();

        if let Some(node) = self.nodes.get(id) {
            for parent in &node.parents {
                queue.push_back(parent.clone());
                ancestors.insert(parent.clone());
            }
        }

        while let Some(current_id) = queue.pop_front() {
            if let Some(node) = self.nodes.get(&current_id) {
                for parent in &node.parents {
                    if !ancestors.contains(parent) {
                        ancestors.insert(parent.clone());
                        queue.push_back(parent.clone());
                    }
                }
            }
        }

        ancestors
    }

    /// Obtener todos los descendientes de un nodo
    pub fn get_descendants(&self, id: &[u8]) -> HashSet<Vec<u8>> {
        let mut descendants = HashSet::new();
        let mut queue = VecDeque::new();

        if let Some(node) = self.nodes.get(id) {
            for child in &node.children {
                queue.push_back(child.clone());
                descendants.insert(child.clone());
            }
        }

        while let Some(current_id) = queue.pop_front() {
            if let Some(node) = self.nodes.get(&current_id) {
                for child in &node.children {
                    if !descendants.contains(child) {
                        descendants.insert(child.clone());
                        queue.push_back(child.clone());
                    }
                }
            }
        }

        descendants
    }

    /// Selección inteligente de tips usando el algoritmo GHOSTDAG
    pub fn select_tips_ghostdag(&self, k: usize) -> Vec<Vec<u8>> {
        if self.tips.is_empty() {
            return vec![];
        }

        // Calcular puntajes GHOSTDAG para cada tip
        let mut scored_tips: Vec<(Vec<u8>, f64)> = self
            .tips
            .iter()
            .map(|tip| {
                let score = self.calculate_ghostdag_score(tip);
                (tip.clone(), score)
            })
            .collect();

        // Ordenar por puntaje descendente
        scored_tips.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));

        // Tomar los k mejores tips
        scored_tips.into_iter().take(k).map(|(id, _)| id).collect()
    }

    /// Calcular puntaje GHOSTDAG para un nodo
    fn calculate_ghostdag_score(&self, id: &[u8]) -> f64 {
        let ancestors = self.get_ancestors(id);
        let mut score = ancestors.len() as f64;

        // Bonus por altura
        if let Some(node) = self.nodes.get(id) {
            score += node.height as f64 * 0.1;

            // Bonus por tiempo reciente
            let age = chrono::Utc::now().timestamp() as u64 - node.timestamp;
            if age < 60 {
                score += 10.0; // Bonus para nodos muy recientes
            }
        }

        score
    }

    /// Encontrar el ancestro común más reciente (LCA) de dos nodos
    pub fn find_lca(&self, id1: &[u8], id2: &[u8]) -> Option<Vec<u8>> {
        let ancestors1 = self.get_ancestors(id1);
        let ancestors2 = self.get_ancestors(id2);

        // Encontrar ancestros comunes
        let common: HashSet<_> = ancestors1.intersection(&ancestors2).cloned().collect();

        // Encontrar el de mayor altura (más reciente)
        common
            .into_iter()
            .filter_map(|id| self.nodes.get(&id).map(|n| (id, n.height)))
            .max_by_key(|(_, height)| *height)
            .map(|(id, _)| id)
    }

    /// Comprimir el DAG eliminando nodos antiguos confirmados
    pub fn prune_old_nodes(&mut self, keep_height: u64) -> usize {
        let to_remove: Vec<Vec<u8>> = self
            .nodes
            .iter()
            .filter_map(|(id, node)| {
                if node.height < keep_height && self.tips.contains(id) == false {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        let removed_count = to_remove.len();

        for id in to_remove {
            self.remove_node(&id);
        }

        info!("Pruned {} old nodes from DAG", removed_count);
        removed_count
    }

    /// Eliminar un nodo del DAG
    fn remove_node(&mut self, id: &[u8]) {
        if let Some(node_index) = self.id_to_node_index.remove(id) {
            self.graph.remove_node(node_index);
        }

        if let Some(node) = self.nodes.remove(id) {
            // Actualizar padres y hijos
            for parent_id in &node.parents {
                if let Some(parent) = self.nodes.get_mut(parent_id) {
                    parent.children.retain(|c| c != id);

                    // Si el padre no tiene más hijos, vuelve a ser tip
                    if parent.children.is_empty() {
                        self.tips.insert(parent_id.clone());
                    }
                }
            }

            for child_id in &node.children {
                if let Some(child) = self.nodes.get_mut(child_id) {
                    child.parents.retain(|p| p != id);

                    // Si el hijo no tiene más padres, se convierte en raíz
                    if child.parents.is_empty() {
                        self.roots.insert(child_id.clone());
                    }
                }
            }
        }

        self.tips.remove(id);
        self.roots.remove(id);
    }

    /// Obtener estadísticas del DAG
    pub fn get_statistics(&self) -> DAGStatistics {
        DAGStatistics {
            total_nodes: self.nodes.len(),
            tips_count: self.tips.len(),
            roots_count: self.roots.len(),
            max_height: self.nodes.values().map(|n| n.height).max().unwrap_or(0),
            has_cycles: self.has_cycles(),
            average_parents: if self.nodes.is_empty() {
                0.0
            } else {
                self.nodes
                    .values()
                    .map(|n| n.parents.len() as f64)
                    .sum::<f64>()
                    / self.nodes.len() as f64
            },
        }
    }

    /// Obtener los tips actuales del DAG
    pub fn get_tips(&self) -> Vec<Vec<u8>> {
        self.tips.iter().cloned().collect()
    }

    /// Obtener un nodo por ID
    pub fn get_node(&self, id: &[u8]) -> Option<&DAGNode<T>> {
        self.nodes.get(id)
    }

    /// Verificar si un nodo existe en el DAG
    pub fn contains(&self, id: &[u8]) -> bool {
        self.nodes.contains_key(id)
    }
}

/// Estadísticas del DAG
#[derive(Debug, Clone)]
pub struct DAGStatistics {
    pub total_nodes: usize,
    pub tips_count: usize,
    pub roots_count: usize,
    pub max_height: u64,
    pub has_cycles: bool,
    pub average_parents: f64,
}

/// DAG especializado para bloques
pub type BlockDAG = DAG<Block>;

/// DAG especializado para transacciones
pub type TransactionDAG = DAG<Transaction>;

impl BlockDAG {
    /// Agregar un bloque al DAG
    pub fn add_block(&mut self, block: Block) -> AvoResult<()> {
        let id = block.id.0.to_vec();
        let parents: Vec<Vec<u8>> = block.parents.iter().map(|p| p.0.to_vec()).collect();
        let timestamp = block.timestamp;

        self.add_node(id, block, parents, timestamp)
    }

    /// Obtener ordenamiento de bloques
    pub fn get_block_ordering(&self) -> AvoResult<Vec<BlockId>> {
        let sorted = self.topological_sort()?;
        Ok(sorted
            .into_iter()
            .map(|id| {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&id[..32.min(id.len())]);
                BlockId(hash)
            })
            .collect())
    }
}

impl TransactionDAG {
    /// Agregar una transacción al DAG
    pub fn add_transaction(&mut self, tx: Transaction) -> AvoResult<()> {
        let id = tx.id.0.to_vec();
        let parents: Vec<Vec<u8>> = tx.parents.iter().map(|p| p.0.to_vec()).collect();
        let timestamp = chrono::Utc::now().timestamp() as u64;

        self.add_node(id, tx, parents, timestamp)
    }

    /// Obtener ordenamiento de transacciones
    pub fn get_transaction_ordering(&self) -> AvoResult<Vec<TransactionId>> {
        let sorted = self.topological_sort()?;
        Ok(sorted
            .into_iter()
            .map(|id| {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&id[..32.min(id.len())]);
                TransactionId(hash)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dag_basic_operations() {
        let mut dag = DAG::<String>::new();

        // Agregar nodos
        dag.add_node(vec![1], "A".to_string(), vec![], 1).unwrap();
        dag.add_node(vec![2], "B".to_string(), vec![vec![1]], 2)
            .unwrap();
        dag.add_node(vec![3], "C".to_string(), vec![vec![1]], 3)
            .unwrap();
        dag.add_node(vec![4], "D".to_string(), vec![vec![2], vec![3]], 4)
            .unwrap();

        // Verificar estructura
        assert_eq!(dag.nodes.len(), 4);
        assert_eq!(dag.tips.len(), 1);
        assert!(dag.tips.contains(&vec![4]));
        assert!(!dag.has_cycles());

        // Verificar ordenamiento topológico
        let sorted = dag.topological_sort().unwrap();
        assert_eq!(sorted.len(), 4);
        assert_eq!(sorted[0], vec![1]); // A debe ser primero
    }

    #[test]
    fn test_cycle_detection() {
        let mut dag = DAG::<String>::new();

        dag.add_node(vec![1], "A".to_string(), vec![], 1).unwrap();
        dag.add_node(vec![2], "B".to_string(), vec![vec![1]], 2)
            .unwrap();

        // Intentar crear un ciclo
        let result = dag.add_node(vec![1], "A2".to_string(), vec![vec![2]], 3);
        assert!(result.is_err());
        assert!(!dag.has_cycles());
    }
}
