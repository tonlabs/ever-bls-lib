use crate::{fail, Result};
use std::collections::HashMap;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NodesInfo {
    pub map: HashMap<u16, u16>,
    pub total_num_of_nodes: u16,
}

impl NodesInfo {
    pub fn create_node_info(total_num_of_nodes: u16, node_index: u16) -> Result<Self> {
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        if node_index >= total_num_of_nodes {
            fail!("Index of node can not be greater than total number of nodes!");
        }
        let mut info = HashMap::new();
        let num_of_occurrences = 1;
        info.insert(node_index, num_of_occurrences);
        Ok(Self {
            map: info,
            total_num_of_nodes,
        })
    }

    pub fn with_data(info: HashMap<u16, u16>, total_num_of_nodes: u16) -> Result<Self> {
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        if info.len() == 0 {
            fail!("Node info should not be empty!")
        }
        for (index, number_of_occurrence) in &info {
            if *index >= total_num_of_nodes {
                fail!("Index of node can not be greater than total number of nodes!")
            }
            if *number_of_occurrence == 0 {
                fail!("Number of occurrence for node can not be zero!")
            }
        }
        let nodes_info = NodesInfo {
            map: info,
            total_num_of_nodes,
        };
        Ok(nodes_info)
    }

    pub fn print(&self) {
        println!("--------------------------------------------------");
        println!("Total number of nodes: {}", &self.total_num_of_nodes);
        println!("Indexes -- occurrences: ");
        for (index, number_of_occurrence) in &self.map {
            println!("{}: \"{}\"", index, number_of_occurrence);
        }
        println!("--------------------------------------------------");
        println!("--------------------------------------------------");
    }

    pub fn merge(info1: &NodesInfo, info2: &NodesInfo) -> Result<NodesInfo> {
        if info1.total_num_of_nodes != info2.total_num_of_nodes {
            fail!("Total number of nodes must be the same!");
        }
        let mut new_info = info1.map.clone();
        for (index, number_of_occurrence) in &info2.map {
            new_info.insert(
                *index,
                if new_info.contains_key(&index) {
                    new_info[index] + *number_of_occurrence
                   } else {
                    *number_of_occurrence
                   },
            );
        }
        Ok(NodesInfo {
            map: new_info,
            total_num_of_nodes: info1.total_num_of_nodes,
        })
    }

    pub fn merge_multiple(info_vec: &Vec<&NodesInfo>) -> Result<NodesInfo> {
        if info_vec.len() <= 1 {
            fail!("Nodes info collection must have at least two elements!!")
        }
        let mut final_nodes_info = NodesInfo::merge(&info_vec[0], &info_vec[1])?;
        for i in 2..info_vec.len() {
            final_nodes_info = NodesInfo::merge(&final_nodes_info, &info_vec[i])?;
        }
        Ok(final_nodes_info)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result_vec = Vec::new();
        let total_num_of_nodes = &self.total_num_of_nodes;
        let total_num_of_nodes_bytes = total_num_of_nodes.to_be_bytes();
        result_vec.extend_from_slice(&total_num_of_nodes_bytes);
        for (index, number_of_occurrence) in &self.map {
            let index_bytes = index.to_be_bytes();
            result_vec.extend_from_slice(&index_bytes);
            let number_of_occurrence_bytes = number_of_occurrence.to_be_bytes();
            result_vec.extend_from_slice(&number_of_occurrence_bytes);
        }
        result_vec
    }

    pub fn deserialize(info_bytes: &Vec<u8>) -> Result<NodesInfo> {
        if info_bytes.len() <= 2 || (info_bytes.len() % 4) != 2 {
            fail!("node_info_bytes must have non zero length (> 2) being of form 4*k+2!");
        }
        let total_num_of_nodes = ((info_bytes[0] as u16) << 8) | info_bytes[1] as u16;
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        let mut new_info = HashMap::new();
        for i in (2..info_bytes.len()).step_by(4) {
            let index = ((info_bytes[i] as u16) << 8) | info_bytes[i + 1] as u16;
            if index >= total_num_of_nodes {
                fail!("Index can not be greater than total_num_of_nodes!");
            }
            let number_of_occurrence = ((info_bytes[i + 2] as u16) << 8) | info_bytes[i + 3] as u16;
            new_info.insert(index, number_of_occurrence);
        }

        NodesInfo::with_data(new_info, total_num_of_nodes)
    }
}


