
// This code only works with `usize` of at least 32 bits.
#[cfg(target_pointer_width = "16")]
compile_error!("cannot build on 16 bit systems");


use std::{fmt, mem};
use crate::api::roa::{AsNumber, Ipv4Prefix, Ipv6Prefix};


//------------ RouteOriginCollection -----------------------------------------

#[derive(Clone, Debug)]
pub struct RouteOriginCollection<P> {
    tree: Box<[TreeNode]>,
    tree_root_idx: OptIndex,
    data: RouteOriginBox<P>,
}

impl<P: RoutePrefix> RouteOriginCollection<P> {
    pub fn new(data: Vec<RouteOrigin<P>>) -> Result<Self, LargeIndex> {
        let mut data = data.into_boxed_slice();
        data.sort();
        let data = RouteOriginBox(data);

        let Some(first) = data.0.first() else {
           return Ok(Self {
                tree: Box::new([]),
                tree_root_idx: OptIndex::none(),
                data: RouteOriginBox(Box::new([])),
            })
        };

        let mut tree = Vec::new();
        let (tree_root_idx, data_idx) = Self::create_children(
            &mut tree,
            (first.prefix == P::default()).then_some(0),
            &data
        )?;

        debug_assert!(data_idx.is_none());
        Ok(Self {
            tree: tree.into_boxed_slice(),
            tree_root_idx,
            data,
        })

        /*
        let mut next_data_idx = 0;
        let mut last_node_idx = OptIndex::none();

        loop {
            let (node_idx, data_idx) = Self::create_children(
                &mut tree, next_data_idx, &data
            )?;
            if let Some(data_idx) = data_idx {
                // There is more data. If we had a previous node, we need
                // to add an empty node before continuing.
                if last_node_idx.is_some() {
                    last_node_idx = Self::push_node(
                        TreeNode::with_children(
                            OptIndex::none(),
                            last_node_idx, node_idx
                        ),
                        &mut tree
                    )?
                }
                else {
                    last_node_idx = node_idx
                }
                next_data_idx = data_idx;
            }
            else {
                // All data covered. If we have a previous node idx, we need
                // to add an empty node. Otherwise the node_idx is the root.
                let tree_root_idx = if last_node_idx.is_some() {
                    Self::push_node(
                        TreeNode::with_children(
                            OptIndex::none(),
                            last_node_idx, node_idx
                        ),
                        &mut tree
                    )?
                }
                else {
                    node_idx
                };

                return Ok(Self {
                    tree: tree.into_boxed_slice(),
                    tree_root_idx,
                    data
                })
            }
        }
        */
    }

    pub fn size(&self) -> usize {
        mem::size_of::<TreeNode>() * self.tree.len()
            + mem::size_of::<RouteOrigin<P>>() * self.data.0.len()
    }

    pub fn tree_size(&self) -> usize {
        mem::size_of::<TreeNode>() * self.tree.len()
    }

    pub fn data_size(&self) -> usize {
        mem::size_of::<RouteOrigin<P>>() * self.data.0.len()
    }

    pub fn tree_len(&self) -> usize {
        self.tree.len()
    }
    
    pub fn data_len(&self) -> usize {
        self.data.0.len()
    }

    pub fn empty_tree_len(&self) -> usize {
        self.tree.iter().filter(|item| item.data.is_none()).count()
    }

    fn create_children(
        tree: &mut Vec<TreeNode>,
        data_idx: Option<usize>,
        data: &RouteOriginBox<P>
    ) -> Result<(OptIndex, Option<usize>), LargeIndex> {
        let opt_data_idx: OptIndex = data_idx.try_into()?;

        let (my_prefix, mut next_data_idx) = match data_idx {
            Some(data_idx) => {
                debug_assert!(data_idx < data.0.len());

                // Get the index of the next prefix. If there isn’t one, add
                // us as a leaf node and return.
                let Some(next_data_idx) = data.next_prefix(data_idx) else {
                    return Ok((
                        Self::push_node(TreeNode::new(opt_data_idx), tree)?,
                        None
                    ))
                };

                (data.0[data_idx].prefix, next_data_idx)
            }
            None => {
                (P::default(), 0)
            }
        };

        let mut next_prefix = data.0[next_data_idx].prefix;

        // If we don’t cover the next prefix, we are a leaf node and can
        // return.
        if !my_prefix.covers(next_prefix) {
            return Ok((
                Self::push_node(TreeNode::new(opt_data_idx), tree)?,
                Some(next_data_idx)
            ))
        }

        // Now build the left sub-tree.
        //
        // We only have a left child if the next prefix has the next bit not
        // set. In this case, we recursively build the sub-tree for the next
        // node which will also give us an updated next prefix. Because we
        // don’t have a complete tree, this next prefix may still be on the
        // left side. If that happens, we to build the sub-tree for that new
        // next node and then insert an empty node with the first tree on
        // the left and the second tree on the right. And then check the now
        // new next prefix again. And so on.
        let mut left_idx = OptIndex::none();
        while
            my_prefix.covers(next_prefix)
            && !next_prefix.bit(my_prefix.addr_len())
        {
            let (node_idx, post_data_idx) = Self::create_children(
                tree, Some(next_data_idx), data
            )?;

            if left_idx.is_some() {
                // If we have a left_idx, we need to insert an empty node
                // which will then become the new left_idx.
                left_idx = Self::push_node(
                    TreeNode::with_children(
                        OptIndex::none(), left_idx, node_idx
                    ),
                    tree,
                )?;

                let Some(post_data_idx) = post_data_idx else {
                    return Ok((
                        Self::push_node(
                            TreeNode::with_children(
                                opt_data_idx, left_idx, OptIndex::none()
                            ),
                            tree,
                        )?,
                        None
                    ))
                };
                next_data_idx = post_data_idx;
            }
            else {
                let Some(post_data_idx) = post_data_idx else {
                    return Ok((
                        Self::push_node(
                            TreeNode::with_children(
                                opt_data_idx, node_idx, OptIndex::none()
                            ),
                            tree,
                        )?,
                        None
                    ))
                };
                left_idx = node_idx;
                next_data_idx = post_data_idx;
            }
            next_prefix = data.0[next_data_idx].prefix;
        }

        // Now build the right sub-tree.
        //
        // This is basically the same as above, but we only check for
        // coverage since, given that the data is sorted, anything covered
        // must have the next bit set.
        let mut right_idx = OptIndex::none();
        while my_prefix.covers(next_prefix) {
            let (node_idx, post_data_idx) = Self::create_children(
                tree, Some(next_data_idx), data
            )?;

            if right_idx.is_some() {
                right_idx = Self::push_node(
                    TreeNode::with_children(
                        OptIndex::none(), right_idx, node_idx
                    ),
                    tree,
                )?;

                let Some(post_data_idx) = post_data_idx else {
                    return Ok((
                        Self::push_node(
                            TreeNode::with_children(
                                opt_data_idx, left_idx, right_idx
                            ),
                            tree,
                        )?,
                        None
                    ))
                };
                next_data_idx = post_data_idx;
            }
            else {
                let Some(post_data_idx) = post_data_idx else {
                    return Ok((
                        Self::push_node(
                            TreeNode::with_children(
                                opt_data_idx, left_idx, node_idx
                            ),
                            tree,
                        )?,
                        None
                    ))
                };
                right_idx = node_idx;
                next_data_idx = post_data_idx;
            }
            next_prefix = data.0[next_data_idx].prefix;
        }

        Ok((
            Self::push_node(
                TreeNode::with_children(
                    opt_data_idx, left_idx, right_idx
                ),
                tree,
            )?,
            Some(next_data_idx),
        ))
    }

    fn push_node(
        node: TreeNode, tree: &mut Vec<TreeNode>
    ) -> Result<OptIndex, LargeIndex> {
        let idx = Some(tree.len()).try_into()?;
        tree.push(node);
        Ok(idx)
    }
}


impl<P: RoutePrefix> RouteOriginCollection<P> {
    pub fn iter(&self) -> TreeIter<'_, P> {
        TreeIter::new(self)
    }

    pub fn matching_or_less_specific(
        &self, prefix: P
    ) -> impl Iterator<Item = &'_ [RouteOrigin<P>]> + '_ {
        LessSpecificIter(LessSpecificIndexIter::new(self, prefix))
    }

    pub fn matching_or_more_specific(
        &self, prefix: P
    ) -> impl Iterator<Item = &'_ [RouteOrigin<P>]> + '_ {
        TreeIter {
            collection: self,
            tree_idx_stack: match self.get_top_for_more(prefix) {
                Some(top) => vec![top],
                None => vec![]
            }
        }
    }

    fn get_top_for_more(
        &self, prefix: P
    ) -> Option<usize> {
        let top_idx = LessSpecificIndexIter::new(self, prefix).last()?;
        let node = self.tree.get(top_idx)?;
        let data = self.data.0.get(node.data.into_usize()?)?;
        if data.prefix == prefix {
            Some(top_idx)
        }
        else if prefix.bit(data.prefix.addr_len()) {
            node.right.into_usize()
        }
        else {
            node.left.into_usize()
        }
    }
}


//------------ RoutePrefix ---------------------------------------------------

/// The implementatin of `Default` must return the slash zero prefix.
pub trait RoutePrefix: Clone + Copy + Default + fmt::Debug + Eq + Ord {
    fn covers(self, other: Self) -> bool;

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


//------------ OptIndex ------------------------------------------------------

/// An optional index into a slice.
///
/// This type wraps a u32 to be smaller than a usize. It uses `u32::MAX`
/// as the sentinel for `None`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OptIndex(u32);

impl OptIndex {
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

impl Default for OptIndex {
    fn default() -> Self {
        Self::none()
    }
}

impl TryFrom<Option<usize>> for OptIndex {
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

impl TryFrom<usize> for OptIndex {
    type Error = LargeIndex;

    fn try_from(src: usize) -> Result<Self, Self::Error> {
        Some(src).try_into()
    }
}

impl From<OptIndex> for Option<usize> {
    fn from(src: OptIndex) -> Self {
        if src.0 == u32::MAX {
            None
        }
        else {
            Some(src.0 as usize)
        }
    }
}


//------------ TreeNode ------------------------------------------------------

/// A node in the radix tree.
#[derive(Clone, Copy, Debug, Default)]
struct TreeNode {
    /// The index of the data item referred to by this node.
    ///
    /// This is an optional index into the data slice.
    data: OptIndex,

    /// The index of the left child tree node.
    ///
    /// This is an optional index into the same tree slice.
    ///
    /// The left child is the prefix with at least one more bit where the
    /// next bit is 0. 
    left: OptIndex,

    /// The right child tree node.
    ///
    /// This is an optional index into the same tree slice.
    ///
    /// The left child is the prefix with at least one more bit where the
    /// next bit is 1. 
    right: OptIndex,
}

impl TreeNode {
    fn new(data: OptIndex) -> Self {
        Self {
            data,
            left: OptIndex::none(),
            right: OptIndex::none(),
        }
    }

    fn with_children(
        data: OptIndex, left: OptIndex, right: OptIndex
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
    fn next_prefix(&self, idx: usize) -> Option<usize> {
        let mut next_idx = idx;
        loop {
            next_idx = match next_idx.checked_add(1) {
                Some(idx) => idx,
                None => return None,
            };
            if next_idx >= self.0.len() {
                return None;
            }
            if self.0[next_idx].prefix != self.0[idx].prefix {
                return next_idx.try_into().ok();
            }
        }
    }

    fn prefix_slice(&self, idx: usize) -> &'_ [RouteOrigin<P>] {
        let next = self.next_prefix(idx).unwrap_or(self.0.len());
        self.0.get(idx..next).unwrap_or(&[])
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
        res.find_top();
        res
    }

    fn find_top(&mut self) {
        let Some(node) = self.collection.tree.get(0) else { return };
        if let Some(data_idx) = node.data.into_usize() {
            let Some(data) = self.collection.data.0.get(data_idx) else {
                return
            };
            if data.prefix.covers(self.prefix) {
                self.tree_idx = Some(0);
            }
        }
        else {
            if let Ok(Some(idx)) = self.find_recursive(node.left) {
                self.tree_idx = Some(idx);
            }
            else if let Ok(Some(idx)) = self.find_recursive(node.right) {
                self.tree_idx = Some(idx);
            }
        }
    }

    fn find_next(&self, current_node: TreeNode) -> Option<usize> {
        let current_prefix = self.collection.data.0.get(
            current_node.data.into_usize()?
        )?.prefix;
        if current_prefix.addr_len() >= self.prefix.addr_len() {
            return None
        }
        if !self.prefix.bit(current_prefix.addr_len()) {
            self.find_recursive(current_node.left)
        }
        else {
            self.find_recursive(current_node.right)
        }.ok().flatten()
    }

    // Returns `Ok(None)` if we are done. Returns `Err(())` if this is the
    // wrong branch.
    fn find_recursive(&self, tree_idx: OptIndex) -> Result<Option<usize>, ()> {
        let Some(tree_idx) = tree_idx.into_usize() else {
            return Ok(None)
        };
        let Some(node) = self.collection.tree.get(tree_idx) else {
            return Ok(None)
        };
        match node.data.into_usize() {
            Some(data_idx) => {
                // We have data, so we can decide based on its prefix.
                let Some(prefix) = self.collection.data.0.get(
                    data_idx
                ).map(|data| data.prefix)
                else {
                    return Ok(None)
                };
                if prefix == self.prefix {
                    return Ok(Some(tree_idx))
                }
                if prefix.addr_len() > self.prefix.addr_len() {
                    return Ok(None)
                }
                if !prefix.covers(self.prefix) {
                    // We took a wrong turn somewhere.
                    return Err(())
                }
                if !self.prefix.bit(prefix.addr_len()) {
                    self.find_recursive(node.left)
                }
                else {
                    self.find_recursive(node.right)
                }
            }
            None => {
                // We don’t have data, so we don’t know if we have to go
                // left or right. Just try both.
                if node.left.is_none() && node.right.is_none() {
                    // An empty leaf? How strange.
                    Ok(None)
                }
                else if node.right.is_none() {
                    self.find_recursive(node.left)
                }
                else if node.left.is_none() {
                    self.find_recursive(node.right)
                }
                // They both are some, try left first and try right if that
                // returns an error.
                else if let Ok(left) = self.find_recursive(node.left) {
                    Ok(left)
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


//----------- LessSpecificIter -----------------------------------------------

struct LessSpecificIter<'a, P>(LessSpecificIndexIter<'a, P>);

impl<'a, P: RoutePrefix> Iterator for LessSpecificIter<'a, P> {
    type Item = &'a [RouteOrigin<P>];

    fn next(&mut self) -> Option<Self::Item> {
        let tree_idx = self.0.next()?;
        let node = self.0.collection.tree.get(tree_idx)?;
        let Some(data_idx) = node.data.into_usize() else {
            return None
        };
        Some(self.0.collection.data.prefix_slice(data_idx))
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

impl<'a, P> TreeIter<'a, P> {
    fn new(collection: &'a RouteOriginCollection<P>) -> Self {
        let mut tree_idx_stack = Vec::new();
        if let Some(idx) = collection.tree_root_idx.into_usize() {
            tree_idx_stack.push(idx);
        }
        Self { collection, tree_idx_stack, }
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

            if let Some(idx) = node.data.into_usize() {
                return Some(self.collection.data.prefix_slice(idx))
            }
        }
    }
}



//=========== Error Types ====================================================

//----------- LargeIndex -----------------------------------------------------

#[derive(Debug)]
pub struct LargeIndex(());





//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use rpki::repository::resources::Prefix;
    use super::*;

    fn tree(
        items: &[(&'static str, u32)]
    ) -> RouteOriginCollection<Ipv4Prefix> {
        let data = items.iter().map(|(prefix, asn)| {
            RouteOrigin {
                prefix: Prefix::from_str(prefix).unwrap().into(),
                origin: AsNumber::from_u32(*asn)
            }
        }).collect();
        RouteOriginCollection::new(data).unwrap()
    }

    fn ro(prefix: &'static str, origin: u32) -> RouteOrigin<Ipv4Prefix> {
        RouteOrigin {
            prefix: Prefix::from_str(prefix).unwrap().into(),
            origin: AsNumber::from_u32(origin)
        }
    }

    #[test]
    fn iter() {
        let tree = tree(&[
            ("10.0.0.0/24", 64496),
            ("10.0.1.0/24", 64496),
            ("10.0.0.0/23", 64496),
            ("10.0.0.0/20", 64496),
            ("10.0.0.0/16", 64496),
        ]);
        assert_eq!(
            tree.iter().collect::<Vec<_>>(),
            [
                [ro("10.0.0.0/16", 64496)],
                [ro("10.0.0.0/20", 64496)],
                [ro("10.0.0.0/23", 64496)],
                [ro("10.0.0.0/24", 64496)],
                [ro("10.0.1.0/24", 64496)],
            ]
        );
    }

    #[test]
    fn size() {
        eprintln!("tree item: {},\n v4 data item: {}\n v6 data item: {}",
            mem::size_of::<TreeNode>(),
            mem::size_of::<RouteOrigin<Ipv4Prefix>>(),
            mem::size_of::<RouteOrigin<Ipv6Prefix>>(),
        );
    }

/*
    fn ann(s: &str) -> Announcement {
        Announcement::from_str(s).unwrap()
    }

    fn pfx(s: &str) -> TypedPrefix {
        TypedPrefix::from_str(s).unwrap()
    }

    fn range_pfx(s: &str) -> IpRange {
        IpRange::from(&pfx(s))
    }

    fn make_test_tree() -> TypedPrefixTree<Announcement> {
        let mut builder = TypedPrefixTreeBuilder::default();
        builder.add(ann("10.0.0.0/24 => 64496"));
        builder.add(ann("10.0.1.0/24 => 64496"));
        builder.add(ann("10.0.0.0/23 => 64496"));
        builder.add(ann("10.0.0.0/20 => 64496"));
        builder.add(ann("10.0.0.0/16 => 64496"));
        builder.build()
    }

    #[test]
    fn range_contains() {
        let more_specific_1 = range_pfx("10.0.0.0/24");
        let more_specific_2 = range_pfx("10.0.1.0/24");
        let test_pfx = range_pfx("10.0.0.0/23");

        assert!(test_pfx.contains(&more_specific_1.0));
        assert!(test_pfx.contains(&more_specific_2.0));
    }

    #[test]
    fn typed_prefix_tree_more_specific() {
        let tree = make_test_tree();
        let search = TypedPrefix::from_str("10.0.0.0/23").unwrap();
        assert_eq!(3, tree.matching_or_more_specific(search).len());

        let search = TypedPrefix::from_str("10.0.2.0/24").unwrap();
        assert_eq!(0, tree.matching_or_more_specific(search).len());
    }

    #[test]
    fn typed_prefix_tree_less_specific() {
        let tree = make_test_tree();
        let search = TypedPrefix::from_str("10.0.0.0/23").unwrap();
        assert_eq!(3, tree.matching_or_less_specific(search).len());

        let search = TypedPrefix::from_str("10.0.0.0/24").unwrap();
        assert_eq!(4, tree.matching_or_less_specific(search).len());

        let search = TypedPrefix::from_str("10.0.0.0/16").unwrap();
        assert_eq!(1, tree.matching_or_less_specific(search).len());

        let search = TypedPrefix::from_str("10.0.0.0/15").unwrap();
        assert_eq!(0, tree.matching_or_less_specific(search).len());
    }

    #[test]
    fn set_to_ranges() {
        let asns = "AS65000-AS65003, AS65005";
        let ipv4s = "10.0.0.0/8, 192.168.0.0";
        let ipv6s = "::1, 2001:db8::/32";
        let set = ResourceSet::from_strs(asns, ipv4s, ipv6s).unwrap();

        let (v4_ranges, v6_ranges) = IpRange::for_resource_set(&set);
        assert_eq!(2, v4_ranges.len());
        assert_eq!(2, v6_ranges.len());
    }
*/
}

