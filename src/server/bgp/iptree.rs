#![allow(dead_code)]

// This code only works with `usize` of at least 32 bits.
#[cfg(target_pointer_width = "16")]
compile_error!("cannot build on 16 bit systems");


use std::{cmp, fmt, mem};
use crate::api::roa::{AsNumber, Ipv4Prefix, Ipv6Prefix};


//------------ RouteOriginCollection -----------------------------------------

#[derive(Clone, Debug)]
pub struct RouteOriginCollection<P> {
    tree: Box<[TreeNode]>,
    tree_root_idx: TreeIndex,
    data: RouteOriginBox<P>,
    no_data: Box<[P]>,
}

impl<P: RoutePrefix> RouteOriginCollection<P> {
    pub fn new(data: Vec<RouteOrigin<P>>) -> Result<Self, LargeIndex> {
        CollectionBuilder::new(data).process()
    }

    pub fn size(&self) -> usize {
        self.tree_size() + self.data_size() + self.no_data_size()
    }

    pub fn tree_size(&self) -> usize {
        mem::size_of::<TreeNode>() * self.tree.len()
    }

    pub fn data_size(&self) -> usize {
        mem::size_of::<RouteOrigin<P>>() * self.data.0.len()
    }

    pub fn no_data_size(&self) -> usize {
        mem::size_of::<P>() * self.no_data.len()
    }

    pub fn tree_len(&self) -> usize {
        self.tree.len()
    }

    pub fn data_len(&self) -> usize {
        self.data.0.len()
    }

    pub fn unique_data_len(&self) -> usize {
        let mut res = 0;
        let mut idx = 0;
        while idx < self.data.0.len() {
            res += 1;
            idx = self.data.next_prefix(idx);
        }
        res
    }

    pub fn no_data_len(&self) -> usize {
        self.no_data.len()
    }

    pub fn max_depth(&self) -> usize {
        self._max_depth(self.tree_root_idx, 0)
    }

    fn _max_depth(&self, tree_idx: TreeIndex, depth: usize) -> usize {
        let Some(node) = self.get_tree_node(tree_idx) else {
            return depth
        };
        cmp::max(
            self._max_depth(node.left, depth + 1),
            self._max_depth(node.right, depth + 1),
        )
    }

    pub fn empty_nodes(&self) -> usize {
        self.tree.iter().filter(|item| {
            item.data.into_data().is_err()
        }).count()
    }

    pub fn empty_singles(&self) -> usize {
        self.tree.iter().filter(|item| {
            item.data.into_data().is_err()
            & (
                item.left.is_none() || item.right.is_none()
            )
        }).count()
    }

    pub fn iter(&self) -> TreeIter<'_, P> {
        TreeIter::new(self)
    }

    pub fn less_specific(&self, prefix: P) -> LessSpecificIter<'_, P> {
        LessSpecificIter(LessSpecificIndexIter::new(self, prefix))
    }

    pub fn more_specific(&self, prefix: P) -> TreeIter<'_, P> {
        TreeIter::more_specific(self, prefix)
    }
}

impl<P: RoutePrefix> RouteOriginCollection<P> {
    fn get_tree_node(&self, tree_idx: TreeIndex) -> Option<TreeNode> {
        self.tree.get(tree_idx.into_usize()?).copied()
    }

    fn get_data_prefix(&self, data_idx: DataIndex) -> Option<P> {
        match data_idx.into_data() {
            Ok(data_idx) => Some(self.data.0.get(data_idx)?.prefix),
            Err(no_data_idx) => self.no_data.get(no_data_idx).copied(),
        }
    }
}


//------------ CollectionBuilder ---------------------------------------------

struct CollectionBuilder<P> {
    tree: Vec<TreeNode>,
    no_data: Vec<P>,
    data: RouteOriginBox<P>,
    next_data_idx: usize,
}

impl<P: RoutePrefix> CollectionBuilder<P> {
    fn new(data: Vec<RouteOrigin<P>>) -> Self {
        let mut data = data.into_boxed_slice();
        data.sort();
        let data = RouteOriginBox(data);

        Self {
            tree: Vec::new(),
            no_data: Vec::new(),
            data: data,
            next_data_idx: 0,
        }
    }

    fn process(mut self) -> Result<RouteOriginCollection<P>, LargeIndex> {
        let Some(prefix) = self.next_prefix() else {
            return Ok(RouteOriginCollection {
                tree: Box::new([]),
                tree_root_idx: TreeIndex::none(),
                data: RouteOriginBox(Box::new([])),
                no_data: Box::new([]),
            })
        };

        let node = if prefix == P::default() {
            self.advance_data();
            self.process_node(
                prefix, TreeNode::new(DataIndex::data(0)?)
            )?
        }
        else {
            let data = self.push_no_data(P::default())?;
            self.process_node(
                P::default(), TreeNode::new(data)
            )?
        };
        let tree_root_idx = self.push_node(node)?;
        Ok(RouteOriginCollection {
            tree: self.tree.into_boxed_slice(),
            tree_root_idx,
            data: self.data,
            no_data: self.no_data.into_boxed_slice()
        })
    }

    fn process_node(
        &mut self,
        prefix: P,
        mut node: TreeNode
    ) -> Result<TreeNode, LargeIndex> {
        loop {
            // Get the next prefix or return the node as it is.
            let Some(next_prefix) = self.next_prefix() else {
                return Ok(node)
            };

            // If we don’t cover the next prefix, return the node as it is.
            if !prefix.covers(next_prefix) {
                return Ok(node)
            }

            if !next_prefix.bit(prefix.addr_len()) {
                // Next prefix doesn’t have the next bit set, so it is a left
                // child.
                if let Some(left_idx) = node.left.into_usize() {
                    // If there already is a left child, we need to insert
                    // an empty node at the closest ancestor of the left
                    // child’s prefix and whatever the next prefix turns into.
                    let ancestor_prefix = self.node_prefix(
                        left_idx
                    ).closest_ancestor(next_prefix);
                    let data = self.push_no_data(ancestor_prefix)?;
                    let inter_node = self.process_node(
                        ancestor_prefix,
                        TreeNode::with_children(
                            data, node.left, TreeIndex::none()
                        )
                    )?;
                    node.left = self.push_node(inter_node)?;
                }
                else {
                    // If there isn’t currently a left child, the next item
                    // will become the left child.
                    let left_node = TreeNode::new(
                        DataIndex::data(self.next_data_idx)?
                    );
                    self.advance_data();
                    let left_node = self.process_node(
                        next_prefix, left_node,
                    )?;
                    node.left = self.push_node(left_node)?;
                }
            }
            else {
                // Next prefix doesn’t have the next bit set, so it is a right
                // child.
                if let Some(right_idx) = node.right.into_usize() {
                    // If there already is a right child, we need an empty
                    // node. The current right child will become the left
                    // child of that node.
                    let ancestor_prefix = self.node_prefix(
                        right_idx
                    ).closest_ancestor(next_prefix);
                    let data = self.push_no_data(ancestor_prefix)?;
                    let inter_node = self.process_node(
                        ancestor_prefix,
                        TreeNode::with_children(
                            data, node.right, TreeIndex::none()
                        )
                    )?;
                    node.right = self.push_node(inter_node)?;
                }
                else {
                    // No current right child. Add it.
                    let right_node = TreeNode::new(
                        DataIndex::data(self.next_data_idx)?
                    );
                    self.advance_data();
                    let right_node = self.process_node(
                        next_prefix, right_node
                    )?;
                    node.right = self.push_node(right_node)?;
                }
            }
        }
    }

    fn next_prefix(&self) -> Option<P> {
        self.data.0.get(self.next_data_idx).map(|item| item.prefix)
    }

    fn advance_data(&mut self) {
        self.next_data_idx = self.data.next_prefix(self.next_data_idx);
    }

    fn node_prefix(&self, node_idx: usize) -> P {
        match self.tree[node_idx].data.into_data() {
            Ok(idx) => self.data.0[idx].prefix,
            Err(idx) => self.no_data[idx]
        }
    }

    fn push_node(&mut self, node: TreeNode) -> Result<TreeIndex, LargeIndex> {
        let res = self.tree.len().try_into()?;
        self.tree.push(node);
        Ok(res)
    }

    /// Pushes the prefix to the no-data list and returns the data index.
    fn push_no_data(&mut self, prefix: P) -> Result<DataIndex, LargeIndex> {
        let res = DataIndex::no_data(self.no_data.len())?;
        self.no_data.push(prefix);
        Ok(res)
    }
}


//------------ RoutePrefix ---------------------------------------------------

/// The implementatin of `Default` must return the slash zero prefix.
pub trait RoutePrefix: Clone + Copy + Default + fmt::Debug + Eq + Ord {
    fn covers(self, other: Self) -> bool;

    fn closest_ancestor(self, other: Self) -> Self;

    fn addr_len(self) -> u8;

    // count from left.
    fn bit(self, idx: u8) -> bool;
}

impl RoutePrefix for Ipv4Prefix {
    fn covers(self, other: Self) -> bool {
        if self.addr_len() > other.addr_len() {
            return false
        }
        if self.addr_len() == 32 {
            return self.addr() == other.addr()
        }

        self.addr().to_bits()
            == other.addr().to_bits() & !(u32::MAX >> self.addr_len())
    }

    fn closest_ancestor(self, other: Self) -> Self {
        self.resize(
            cmp::min(
                (self.addr().to_bits() ^ other.addr().to_bits())
                    .leading_zeros() as u8,
                cmp::min(self.addr_len(), other.addr_len())
            )
        )
    }

    fn addr_len(self) -> u8 {
        self.addr_len()
    }

    fn bit(self, idx: u8) -> bool {
        let Some(mask) = 0x8000_0000u32.checked_shr(idx.into()) else {
            return false
        };
        (self.addr().to_bits() & mask) != 0
    }
}

impl RoutePrefix for Ipv6Prefix {
    fn covers(self, other: Self) -> bool {
        if self.addr_len() > other.addr_len() {
            return false
        }
        if self.addr_len() == 128 {
            return self.addr() == other.addr()
        }

        self.addr().to_bits()
            == other.addr().to_bits() & !(u128::MAX >> self.addr_len())
    }

    fn closest_ancestor(self, other: Self) -> Self {
        self.resize(
            cmp::min(
                (self.addr().to_bits() ^ other.addr().to_bits())
                    .leading_zeros() as u8,
                cmp::min(self.addr_len(), other.addr_len())
            )
        )
    }

    fn addr_len(self) -> u8 {
        self.addr_len()
    }

    fn bit(self, idx: u8) -> bool {
        let Some(mask) = const { 1u128 << 127 }.checked_shr(idx.into()) else {
            return false
        };
        (self.addr().to_bits() & mask) != 0
    }
}


//------------ TreeIndex ------------------------------------------------------

/// The optional index of a tree node.
///
/// The index is kept as a u32 and uses `u32::MAX` as the sentinel for `None`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TreeIndex(u32);

impl TreeIndex {
    const fn none() -> Self {
        Self(u32::MAX)
    }

    const fn is_none(self) -> bool {
        self.0 == u32::MAX
    }

    const fn is_some(self) -> bool {
        self.0 != u32::MAX
    }

    fn into_usize(self) -> Option<usize> {
        self.into()
    }
}

impl Default for TreeIndex {
    fn default() -> Self {
        Self::none()
    }
}

impl TryFrom<Option<usize>> for TreeIndex {
    type Error = LargeIndex;

    fn try_from(src: Option<usize>) -> Result<Self, Self::Error> {
        match src {
            Some(src) => {
                match u32::try_from(src) {
                    Ok(src) if src == u32::MAX => Err(LargeIndex(())),
                    Ok(src) => Ok(Self(src)),
                    Err(_) => Err(LargeIndex(())),
                }
            }
            None => Ok(Self(u32::MAX))
        }
    }
}

impl TryFrom<usize> for TreeIndex {
    type Error = LargeIndex;

    fn try_from(src: usize) -> Result<Self, Self::Error> {
        Some(src).try_into()
    }
}

impl From<TreeIndex> for Option<usize> {
    fn from(src: TreeIndex) -> Self {
        if src.0 == u32::MAX {
            None
        }
        else {
            Some(src.0 as usize)
        }
    }
}


//------------ DataIndex -----------------------------------------------------

/// The index of a data item.
///
/// This may either be an index into the data vec or an index into the 
/// non-data vec.
///
/// The index is kept as an u32. If the left-most bit is set, the
/// remaining bits are a data index. If it isn’t, it is a no-data index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DataIndex(u32);

impl DataIndex {
    fn usize_to_u31(idx: usize) -> Result<u32, LargeIndex> {
        match u32::try_from(idx) {
            Ok(idx) if idx & 0x8000_0000 != 0 => Err(LargeIndex(())),
            Ok(idx) => Ok(idx),
            Err(_) => Err(LargeIndex(())),
        }
    }

    fn data(idx: usize) -> Result<Self, LargeIndex> {
        Ok(Self(Self::usize_to_u31(idx)? | 0x8000_0000))
    }

    fn no_data(idx: usize) -> Result<Self, LargeIndex> {
        Ok(Self(Self::usize_to_u31(idx)?))
    }

    fn into_data(self) -> Result<usize, usize> {
        if self.0 & 0x8000_0000 != 0 {
            Ok((self.0 & 0x7FFF_FFFF) as usize)
        }
        else {
            Err(self.0 as usize)
        }
    }

    fn into_no_data(self) -> Result<usize, usize> {
        match self.into_data() {
            Ok(res) => Err(res),
            Err(res) => Ok(res)
        }
    }
}


//------------ TreeNode ------------------------------------------------------

/// A node in the radix tree.
#[derive(Clone, Copy, Debug)]
struct TreeNode {
    /// The index of the data item referred to by this node.
    ///
    /// This is an optional index into the data slice.
    data: DataIndex,

    /// The index of the left child tree node.
    ///
    /// This is an optional index into the same tree slice.
    ///
    /// The left child is the prefix with at least one more bit where the
    /// next bit is 0. 
    left: TreeIndex,

    /// The right child tree node.
    ///
    /// This is an optional index into the same tree slice.
    ///
    /// The left child is the prefix with at least one more bit where the
    /// next bit is 1. 
    right: TreeIndex,
}

impl TreeNode {
    fn new(data: DataIndex) -> Self {
        Self {
            data,
            left: TreeIndex::none(),
            right: TreeIndex::none(),
        }
    }

    fn with_children(
        data: DataIndex, left: TreeIndex, right: TreeIndex
    ) -> Self {
        Self { data, left, right }
    }
}


//------------ RouteOrigin ---------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RouteOrigin<P> {
    /// The address prefix of this route origin.
    pub prefix: P,

    /// The origin AS of this route origin.
    pub origin: AsNumber,
}


//------------ RouteOriginBox ------------------------------------------------

/// A boxed slice of sorted `RouteOrgin`s.
#[derive(Clone, Debug)]
pub struct RouteOriginBox<P>(Box<[RouteOrigin<P>]>);

impl<P: RoutePrefix> RouteOriginBox<P> {
    fn next_prefix(&self, idx: usize) -> usize {
        let mut next_idx = idx;
        loop {
            next_idx = match next_idx.checked_add(1) {
                Some(idx) => idx,
                None => return usize::MAX,
            };
            if next_idx >= self.0.len() {
                return next_idx;
            }
            if self.0[next_idx].prefix != self.0[idx].prefix {
                return next_idx;
            }
        }
    }

    fn prefix_slice(&self, idx: usize) -> &'_ [RouteOrigin<P>] {
        let next = cmp::min(self.next_prefix(idx), self.0.len());
        self.0.get(idx..next).unwrap_or(&[])
    }
}


//----------- TreeIter -------------------------------------------------------

// Iterates: node, then left child recursively, then right child recursively.
pub struct TreeIter<'a, P> {
    collection: &'a RouteOriginCollection<P>,

    /// The stack for recursion.
    ///
    /// The last item is the node we need to process in this call to `next`.
    tree_idx_stack: Vec<usize>,
}

impl<'a, P: RoutePrefix> TreeIter<'a, P> {
    fn new(collection: &'a RouteOriginCollection<P>) -> Self {
        let mut tree_idx_stack = Vec::new();
        if let Some(idx) = collection.tree_root_idx.into_usize() {
            tree_idx_stack.push(idx);
        }
        Self { collection, tree_idx_stack, }
    }

    fn more_specific(
        collection: &'a RouteOriginCollection<P>,
        root_prefix: P
    ) -> Self {
        let mut tree_idx = collection.tree_root_idx;
        while let Some(node) = collection.get_tree_node(tree_idx) {
            let Some(prefix) = collection.get_data_prefix(node.data) else {
                break;
            };
            if prefix.addr_len() >= root_prefix.addr_len() {
                let Some(tree_idx) = tree_idx.into_usize() else {
                    break
                };
                return Self {
                    collection,
                    tree_idx_stack: vec![tree_idx],
                }
            }
            if !root_prefix.bit(prefix.addr_len()) {
                tree_idx = node.left
            }
            else {
                tree_idx = node.right
            }
        }

        Self {
            collection,
            tree_idx_stack: Vec::new()
        }
    }
}

impl<'a, P: RoutePrefix> Iterator for TreeIter<'a, P> {
    type Item = &'a [RouteOrigin<P>];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let node_idx = *self.tree_idx_stack.last()?;
            let node = self.collection.tree.get(node_idx)?;
            self.tree_idx_stack.pop();

            if let Some(idx) = node.right.into_usize() {
                self.tree_idx_stack.push(idx);
            }
            if let Some(idx) = node.left.into_usize() {
                self.tree_idx_stack.push(idx);
            }

            if let Ok(idx) = node.data.into_data() {
                return Some(self.collection.data.prefix_slice(idx))
            }
        }
    }
}


//----------- LessSpecificIter -----------------------------------------------

pub struct LessSpecificIter<'a, P>(LessSpecificIndexIter<'a, P>);

impl<'a, P: RoutePrefix> Iterator for LessSpecificIter<'a, P> {
    type Item = &'a [RouteOrigin<P>];

    fn next(&mut self) -> Option<Self::Item> {
        let tree_idx = self.0.next()?;
        let node = self.0.collection.tree.get(tree_idx)?;
        let Ok(data_idx) = node.data.into_data() else {
            return None
        };
        Some(self.0.collection.data.prefix_slice(data_idx))
    }
}


//----------- LessSpecificIndexIter ------------------------------------------

struct LessSpecificIndexIter<'a, P> {
    collection: &'a RouteOriginCollection<P>,
    prefix: P,
    tree_idx: Option<usize>,
}

impl<'a, P: RoutePrefix> LessSpecificIndexIter<'a, P> {
    fn new(collection: &'a RouteOriginCollection<P>, prefix: P) -> Self {
        let mut res = Self { collection, prefix, tree_idx: None };
        res.tree_idx = res.find_top();
        res
    }

    fn find_top(&self) -> Option<usize> {
        let root = self.collection.get_tree_node(
            self.collection.tree_root_idx
        )?;
        match root.data.into_data() {
            Ok(data_idx) => {
                let root_prefix = self.collection.data.0.get(data_idx)?.prefix;
                if root_prefix.covers(self.prefix) {
                    self.collection.tree_root_idx.into()
                }
                else {
                    None
                }
            }
            Err(_) => {
                self.find_recursive(self.collection.tree_root_idx)
            }
        }
    }

    fn find_next(&self, current_node: TreeNode) -> Option<usize> {
        let current_prefix = self.collection.data.0.get(
            current_node.data.into_data().ok()?
        )?.prefix;
        if current_prefix.addr_len() >= self.prefix.addr_len() {
            return None
        }
        if !self.prefix.bit(current_prefix.addr_len()) {
            self.find_recursive(current_node.left)
        }
        else {
            self.find_recursive(current_node.right)
        }
    }

    fn find_recursive(&self, tree_idx: TreeIndex) -> Option<usize> {
        let node = self.collection.get_tree_node(tree_idx)?;
        match node.data.into_data() {
            Ok(data_idx) => {
                let prefix = self.collection.data.0.get(data_idx)?.prefix;
                if prefix.addr_len() > self.prefix.addr_len() {
                    return None
                }
                else {
                    return tree_idx.into()
                }
            }
            Err(no_data_idx) => {
                let prefix = *self.collection.no_data.get(no_data_idx)?;
                if prefix.addr_len() >= self.prefix.addr_len() {
                    return None
                }
                if !self.prefix.bit(prefix.addr_len()) {
                    self.find_recursive(node.left)
                }
                else {
                    self.find_recursive(node.right)
                }
             }
        }
    }
}

impl<'a, P: RoutePrefix> Iterator for LessSpecificIndexIter<'a, P> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        let tree_idx = self.tree_idx?;
        let node = self.collection.tree.get(tree_idx)?;
        self.tree_idx = self.find_next(*node);
        Some(tree_idx)
    }
}


//=========== Error Types ====================================================

//----------- LargeIndex -----------------------------------------------------

#[derive(Debug)]
pub struct LargeIndex(());

