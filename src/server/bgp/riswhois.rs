//! A tree to keep the RISwhois route origins in.

// This code only works with `usize` of at least 32 bits.
#[cfg(target_pointer_width = "16")]
compile_error!("cannot build on 16 bit systems");

use std::{cmp, error, fmt, io};
use std::io::BufReader;
use std::str::FromStr;
use libflate::gzip;
use crate::api::roa::{AsNumber, Ipv4Prefix, Ipv6Prefix, TypedPrefix};
use crate::api::bgp::Announcement;


//------------ RisWhoisLoader ------------------------------------------------

pub struct RisWhoisLoader {
    v4_url: String,
    v6_url: String,
}

impl RisWhoisLoader {
    pub fn new(v4_url: String, v6_url: String) -> Self {
        Self { v4_url, v6_url }
    }

    pub async fn load(&self) -> Result<RisWhois, RisWhoisError> {
        RisWhois::load(&self.v4_url, &self.v6_url).await
    }
}


//------------ RisWhois ------------------------------------------------------

#[derive(Clone, Default)]
pub struct RisWhois {
    v4: RouteOriginCollection<Ipv4Prefix>,
    v6: RouteOriginCollection<Ipv6Prefix>,
}

impl RisWhois {
    pub fn new(
        v4: RouteOriginCollection<Ipv4Prefix>,
        v6: RouteOriginCollection<Ipv6Prefix>,
    ) -> Self {
        Self { v4, v6 }
    }

    pub async fn load(
        v4_uri: &str, v6_uri: &str
    ) -> Result<Self, RisWhoisError> {
        Ok(Self {
            v4: Self::load_tree(v4_uri).await?,
            v6: Self::load_tree(v6_uri).await?,
        })
    }

    async fn load_tree<P: FromStr + RoutePrefix>(
        uri: &str
    ) -> Result<RouteOriginCollection<P>, RisWhoisError>
    where <P as FromStr>::Err: error::Error + Send + Sync + 'static {
        Self::parse_gz_data(
            &reqwest::get(uri).await.map_err(|err| {
                RisWhoisError::new(uri, io::Error::other(err))
            })?.bytes().await.map_err(|err| {
                RisWhoisError::new(uri, io::Error::other(err))
            })?
        ).map_err(|err| RisWhoisError::new(uri, err))
    }

    fn parse_gz_data<P: FromStr + RoutePrefix>(
        data: &[u8]
    ) -> Result<RouteOriginCollection<P>, io::Error>
    where <P as FromStr>::Err: error::Error + Send + Sync + 'static {
        let data = BufReader::new(
            gzip::Decoder::new(data)?
        );
        Self::parse_data(data)
    }

    fn parse_data<P: FromStr + RoutePrefix>(
        data: impl io::BufRead,
    ) -> Result<RouteOriginCollection<P>, io::Error>
    where <P as FromStr>::Err: error::Error + Send + Sync + 'static {
        let mut res = Vec::new();
        for line in data.lines() {
            let line = line?;
            if line.is_empty() || line.starts_with('%') {
                continue;
            }

            let mut values = line.split_whitespace();

            let asn_str = values.next().ok_or(
                io::Error::other("missing column")
            )?;
            let prefix_str = values.next().ok_or(
                io::Error::other("missing column")
            )?;
            let peers = values.next().ok_or(
                io::Error::other("missing column")
            )?;

            if u32::from_str(peers).map_err(io::Error::other)? <= 5 {
                continue;
            }

            if asn_str.contains('{') {
                continue; // assets not supported (not important here either)
            }

            let origin = AsNumber::from_str(asn_str).map_err(io::Error::other)?;
            let prefix = P::from_str(prefix_str).map_err(|err| {
                eprintln!("{prefix_str}");
                io::Error::other(err)
            })?;

            res.push(RouteOrigin { prefix, origin });
        }

        Ok(RouteOriginCollection::new(res).unwrap())
    }

    pub fn v4(&self) -> &RouteOriginCollection<Ipv4Prefix> {
        &self.v4
    }

    pub fn v6(&self) -> &RouteOriginCollection<Ipv6Prefix> {
        &self.v6
    }
}


//------------ RouteOriginCollection -----------------------------------------

/// A collection of RISwhois route origins.
///
/// This type keeps the route origins for the prefix type `P`, which can be
/// [`Ipv4Prefix`] or [`Ipv6Prefix`]. It is read-only, allowing to iterate
/// over less or more specifics of a given prefix.
#[derive(Clone, Debug)]
pub struct RouteOriginCollection<P> {
    /// The tree part of the collection.
    ///
    /// The tree nodes are essentially three pointers (but we are using
    /// 32 bits to save space): a pointer into data or no-data containing the
    /// prefix for the node plus the origin if it points into actual data,
    /// a pointer to the left child, and a pointer to the right child.
    ///
    /// The left child is the the nearest longer prefix where the next bit
    /// (i.e., the bit at the bit position equal to this prefix’ length) is
    /// zero. The right child has that bit at one. They can, of course, be
    /// “none.”
    ///
    /// “No-data” nodes are added for nodes in the tree whose prefix doesn’t
    /// appear in the data but which are necessary to make the prefix tree
    /// work. Unnecessary no-data node -- those that have only a left child
    /// or only a right child -- are skipped. The result is that a child
    /// node isn’t necessarily for the prefix with an address length plus
    /// one. This is why we need to keep the prefixes.
    ///
    /// A possible optimization (for later) would be to not keep the prefixes
    /// for direct children of a node since we can determine the prefix from
    /// the parent plus whether it is a left or right child. However, that
    /// makes the tree creation algorithm much more complicated, so this has
    /// not yet been done.
    tree: Box<[TreeNode]>,

    /// The index in `tree` of the root node.
    ///
    /// The root node will always be `P::default()`, i.e., the “0/0” prefix.
    /// If it isn’t part of the data, it will be an artifical no-data node.
    tree_root_idx: TreeIndex,

    /// The boxed slice of the data.
    data: RouteOriginBox<P>,

    /// The boxed slice of the “no-data.”
    ///
    /// This contains prefixes of the empty nodes that we had to add to make
    /// the tree work.
    no_data: Box<[P]>,
}

impl<P: RoutePrefix> RouteOriginCollection<P> {
    /// Creates a new collection from the given list of route origins.
    pub fn new(data: Vec<RouteOrigin<P>>) -> Result<Self, LargeDataset> {
        CollectionBuilder::new(data).process()
    }

    /// Returns an iterator over all the route origins in the tree.
    ///
    /// The iterator will walk the tree in order of prefixes, i.e., smaller
    /// addresses first and shorter prefix lengths first.
    pub fn iter(&self) -> TreeIter<'_, P> {
        TreeIter::new(self)
    }

    /// Returns an iterator over all equal or less specific route orgins.
    ///
    /// The iterator will start with the shortest prefix first. If present,
    /// the items will include the origin for the prefix itself.
    pub fn less_specific_or_eq(&self, prefix: P) -> LessSpecificIter<'_, P> {
        LessSpecificIter::new(self, prefix)
    }

    /// Returns an iterator over all equal or more sepcific route origins.
    ///
    /// The iterator will start at the origin for the prefix itself, if
    /// present, and walk the more specific in prefix order.
    pub fn eq_or_more_specific(&self, prefix: P) -> TreeIter<'_, P> {
        TreeIter::more_specific(self, prefix)
    }
}

impl<P: RoutePrefix> RouteOriginCollection<P> {
    /// Returns the node for the given tree index of available.
    fn get_tree_node(&self, tree_idx: TreeIndex) -> Option<TreeNode> {
        self.tree.get(tree_idx.into_usize()?).copied()
    }

    /// Returns the prefix for the given data index of available.
    fn get_data_prefix(&self, data_idx: DataIndex) -> Option<P> {
        match data_idx.into_data() {
            Ok(data_idx) => Some(self.data.0.get(data_idx)?.prefix),
            Err(no_data_idx) => self.no_data.get(no_data_idx).copied(),
        }
    }
}

impl<P> Default for RouteOriginCollection<P> {
    fn default() -> Self {
        Self {
            tree: Box::new([]),
            tree_root_idx: TreeIndex::none(),
            data: RouteOriginBox::default(),
            no_data: Box::new([]),
        }
    }
}


//------------ CollectionBuilder ---------------------------------------------

/// A builder for a route origin collection.
struct CollectionBuilder<P> {
    /// The tree part of the collection.
    ///
    /// See [`RouteOriginCollection`] for details.
    tree: Vec<TreeNode>,

    /// The no-data prefixes.
    ///
    /// See [`RouteOriginCollection`] for details.
    no_data: Vec<P>,

    /// The data route origins.
    ///
    /// See [`RouteOriginCollection`] for details.
    data: RouteOriginBox<P>,

    /// The index in `data` with the item next to process.
    next_data_idx: usize,
}

impl<P: RoutePrefix> CollectionBuilder<P> {
    /// Creates a new collection builder from the route origins.
    fn new(data: Vec<RouteOrigin<P>>) -> Self {
        let mut data = data.into_boxed_slice();
        data.sort();
        let data = RouteOriginBox(data);

        Self {
            tree: Vec::new(),
            no_data: Vec::new(),
            data,
            next_data_idx: 0,
        }
    }

    /// Creates and returns a collection from the builder.
    fn process(mut self) -> Result<RouteOriginCollection<P>, LargeDataset> {
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

    /// Processes the given node.
    ///
    /// Adds the necessary nodes and possibly creates no-data intermediary
    /// nodes. Returns the node that the caller needs to add to the tree.
    fn process_node(
        &mut self,
        prefix: P,
        mut node: TreeNode
    ) -> Result<TreeNode, LargeDataset> {
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

    /// Returns the prefix of the next data item or `None` if we are done.
    fn next_prefix(&self) -> Option<P> {
        self.data.0.get(self.next_data_idx).map(|item| item.prefix)
    }

    /// Advances the next data item.
    fn advance_data(&mut self) {
        self.next_data_idx = self.data.next_prefix(self.next_data_idx);
    }

    /// Returns the node for the given tree node.
    fn node_prefix(&self, node_idx: usize) -> P {
        match self.tree[node_idx].data.into_data() {
            Ok(idx) => self.data.0[idx].prefix,
            Err(idx) => self.no_data[idx]
        }
    }

    /// Appends the given node to the tree, returning its index.
    fn push_node(&mut self, node: TreeNode) -> Result<TreeIndex, LargeDataset> {
        let res = self.tree.len().try_into()?;
        self.tree.push(node);
        Ok(res)
    }

    /// Pushes the prefix to the no-data list and returns the data index.
    fn push_no_data(&mut self, prefix: P) -> Result<DataIndex, LargeDataset> {
        let res = DataIndex::no_data(self.no_data.len())?;
        self.no_data.push(prefix);
        Ok(res)
    }
}


//------------ RoutePrefix ---------------------------------------------------

/// The implementatin of `Default` must return the slash zero prefix.
pub trait RoutePrefix: Clone + Copy + Default + fmt::Debug + Eq + Ord {
    /// Returns whether this prefix covers the given prefix.
    fn covers(self, other: Self) -> bool;

    /// Returns the closest ancestor of the two prefixes.
    fn closest_ancestor(self, other: Self) -> Self;

    /// Returns the address length of the prefix.
    fn addr_len(self) -> u8;

    /// Returns the value of the `idx`th bit of the prefix.
    ///
    /// Bit 0 is the leftmost bit.
    fn bit(self, idx: u8) -> bool;

    /// Converts the prefix into a typed prefix.
    fn into_typed_prefix(self) -> TypedPrefix;
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

    fn into_typed_prefix(self) -> TypedPrefix {
        TypedPrefix::V4(self)
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

    fn into_typed_prefix(self) -> TypedPrefix {
        TypedPrefix::V6(self)
    }
}


//------------ TreeIndex ------------------------------------------------------

/// The optional index of a tree node.
///
/// The index is kept as a u32 and uses `u32::MAX` as the sentinel for `None`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TreeIndex(u32);

impl TreeIndex {
    /// Returns the tree index for “none.”
    const fn none() -> Self {
        Self(u32::MAX)
    }

    /// Converts the tree index into an optional usize.
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
    type Error = LargeDataset;

    fn try_from(src: Option<usize>) -> Result<Self, Self::Error> {
        match src {
            Some(src) => {
                match u32::try_from(src) {
                    Ok(src) if src == u32::MAX => Err(LargeDataset(())),
                    Ok(src) => Ok(Self(src)),
                    Err(_) => Err(LargeDataset(())),
                }
            }
            None => Ok(Self(u32::MAX))
        }
    }
}

impl TryFrom<usize> for TreeIndex {
    type Error = LargeDataset;

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
    /// Returns the 31 bit value for the given usize.
    fn usize_to_u31(idx: usize) -> Result<u32, LargeDataset> {
        match u32::try_from(idx) {
            Ok(idx) if idx & 0x8000_0000 != 0 => Err(LargeDataset(())),
            Ok(idx) => Ok(idx),
            Err(_) => Err(LargeDataset(())),
        }
    }

    /// Returns the index for the given index into the data set.
    fn data(idx: usize) -> Result<Self, LargeDataset> {
        Ok(Self(Self::usize_to_u31(idx)? | 0x8000_0000))
    }

    /// Returns the index for the given index into the no-data set.
    fn no_data(idx: usize) -> Result<Self, LargeDataset> {
        Ok(Self(Self::usize_to_u31(idx)?))
    }

    /// Converts the index into a usize index.
    ///
    /// Returns `Ok(_)` if the index is into the data set and `Err(_)` if the
    /// index is into the no-data set.
    fn into_data(self) -> Result<usize, usize> {
        if self.0 & 0x8000_0000 != 0 {
            Ok((self.0 & 0x7FFF_FFFF) as usize)
        }
        else {
            Err(self.0 as usize)
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
    /// Creates a new node with the data index and no children.
    fn new(data: DataIndex) -> Self {
        Self {
            data,
            left: TreeIndex::none(),
            right: TreeIndex::none(),
        }
    }

    /// Creates a new node with the data index and the given children.
    fn with_children(
        data: DataIndex, left: TreeIndex, right: TreeIndex
    ) -> Self {
        Self { data, left, right }
    }
}


//------------ RouteOrigin ---------------------------------------------------

/// A prefix and an origin AS.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RouteOrigin<P> {
    /// The address prefix of this route origin.
    pub prefix: P,

    /// The origin AS of this route origin.
    pub origin: AsNumber,
}

impl<P: RoutePrefix> From<RouteOrigin<P>> for Announcement {
    fn from(src: RouteOrigin<P>) -> Self {
        Self {
            asn: src.origin,
            prefix: src.prefix.into_typed_prefix()
        }
    }
}


//------------ RouteOriginSet ------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RouteOriginSet<'a, P> {
    slice: &'a [RouteOrigin<P>],
}

impl<'a, P: RoutePrefix> RouteOriginSet<'a, P> {
    fn new(slice: &'a [RouteOrigin<P>]) -> Self {
        debug_assert!(!slice.is_empty());
        Self { slice }
    }

    pub fn prefix(self) -> P {
        // Safety: self.slice is not empty.
        self.slice[0].prefix
    }

    pub fn origins(self) -> impl Iterator<Item = AsNumber> + 'a {
        self.slice.iter().map(|item| item.origin)
    }

    pub fn as_slice(self) -> &'a [RouteOrigin<P>] {
        self.slice
    }

    pub fn iter(self) -> impl Iterator<Item = RouteOrigin<P>> + 'a {
        self.slice.iter().copied()
    }
}


//------------ RouteOriginBox ------------------------------------------------

/// A boxed slice of sorted `RouteOrgin`s.
#[derive(Clone, Debug)]
pub struct RouteOriginBox<P>(Box<[RouteOrigin<P>]>);

impl<P: RoutePrefix> RouteOriginBox<P> {
    /// Returns the index of first following entry with a different prefix.
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

    /// Returns the slice of all entries with the same prefix.
    fn origin_set(&self, idx: usize) -> Option<RouteOriginSet<'_, P>> {
        // XXX Check that this will always return non-empty slices or None.
        let next = cmp::min(self.next_prefix(idx), self.0.len());
        self.0.get(idx..next).map(RouteOriginSet::new)
    }
}

impl<P> Default for RouteOriginBox<P> {
    fn default() -> Self {
        Self(Box::new([]))
    }
}


//----------- TreeIter -------------------------------------------------------

/// An iterator over the items in a route origin collection.
///
/// The iterator goes over the elements in prefix order. That is, prefixes
/// with a smaller integer value go first and, if they are the same, those
/// with a shorter length go first.
///
/// The iterator returns non-empty slices of route origins with the same
/// prefix.
pub struct TreeIter<'a, P> {
    /// A reference to the collection we iterate over.
    collection: &'a RouteOriginCollection<P>,

    /// The stack for recursion.
    ///
    /// The last item is the node we need to process in this call to `next`.
    tree_idx_stack: Vec<usize>,
}

impl<'a, P: RoutePrefix> TreeIter<'a, P> {
    /// Creates a new iterator for the given collection starting at the root.
    fn new(collection: &'a RouteOriginCollection<P>) -> Self {
        let mut tree_idx_stack = Vec::new();
        if let Some(idx) = collection.tree_root_idx.into_usize() {
            tree_idx_stack.push(idx);
        }
        Self { collection, tree_idx_stack, }
    }

    /// Creates a new iterator starting at the given prefix.
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
    type Item = RouteOriginSet<'a, P>;

    fn next(&mut self) -> Option<Self::Item> {
        // We iterate node itself first, then left, then right.
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
                return self.collection.data.origin_set(idx)
            }
        }
    }
}


//----------- LessSpecificIter -----------------------------------------------

/// An iterator over the less specifc entries in a route origin collection.
pub struct LessSpecificIter<'a, P> {
    /// The collection to iterate over.
    collection: &'a RouteOriginCollection<P>,

    /// The prefix to provide less specifics for.
    prefix: P,

    /// The tree index of the item to provide next.
    ///
    /// The item behind this index is returned with the next call to `next`
    /// and updated there before returning.
    tree_idx: Option<usize>,
}

impl<'a, P: RoutePrefix> LessSpecificIter<'a, P> {
    /// Creates a new iterator for the given collection and prefix.
    fn new(collection: &'a RouteOriginCollection<P>, prefix: P) -> Self {
        let mut res = Self { collection, prefix, tree_idx: None };
        res.tree_idx = res.find_top();
        res
    }

    /// Returns the tree index of the first item to return.
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

    /// Finds the index of the item to return after node.
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

    /// Returns the index of the item to return for the given index.
    ///
    /// If the node is a data node, this is the index itself. Otherwise the
    /// method recurses to find the next data node.,
    fn find_recursive(&self, tree_idx: TreeIndex) -> Option<usize> {
        let node = self.collection.get_tree_node(tree_idx)?;
        match node.data.into_data() {
            Ok(data_idx) => {
                let prefix = self.collection.data.0.get(data_idx)?.prefix;
                if prefix.addr_len() > self.prefix.addr_len() {
                    None
                }
                else {
                    tree_idx.into()
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

impl<'a, P: RoutePrefix> Iterator for LessSpecificIter<'a, P> {
    type Item = RouteOriginSet<'a, P>;

    fn next(&mut self) -> Option<Self::Item> {
        let tree_idx = self.tree_idx?;
        let node = self.collection.tree.get(tree_idx)?;
        self.tree_idx = self.find_next(*node);
        let data_idx = node.data.into_data().ok()?;
        self.collection.data.origin_set(data_idx)
    }
}


//=========== Error Types ====================================================

//------------ RisWhoisError ------------------------------------------------

#[derive(Debug)]
pub struct RisWhoisError {
    uri: String,
    err: io::Error,
}

impl RisWhoisError {
    fn new(uri: &str, err: io::Error) -> Self {
        Self { uri: uri.into(), err }
    }
}

impl fmt::Display for RisWhoisError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            "Failed to download RISwhois file `{}`: {}",
            self.uri, self.err
        )
    }
}

//----------- LargeDataset -----------------------------------------------------

/// The dataset is too large to fit into the route origin collection.
#[derive(Debug)]
pub struct LargeDataset(());

impl fmt::Display for LargeDataset {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("RISwhois dataset too large")
    }
}

impl error::Error for LargeDataset { }

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bgp_ris_dumps() {
        let v4 = RisWhois::parse_data(include_bytes!(
            "../../../test-resources/bgp/riswhoisdump.IPv4"
        ).as_ref()).unwrap();
        let v6 = RisWhois::parse_data(include_bytes!(
            "../../../test-resources/bgp/riswhoisdump.IPv6"
        ).as_ref()).unwrap();
        let _ris = RisWhois { v4, v6 };

        /*
        let v4 = ris.v4.iter().map(|item| item[0].prefix).collect::<Vec<_>>();
        for item in v4.windows(2) {
            assert!(item[0] < item[1])
        }
        let v6 = ris.v6.iter().map(|item| item[0].prefix).collect::<Vec<_>>();
        for item in v6.windows(2) {
            assert!(item[0] < item[1])
        }

        for prefix in &v4 {
            let left_vec = v4.iter().copied().filter(|other| {
                prefix.covers(*other)
            }).collect::<Vec<_>>();
            eprintln!("{prefix:?}");
            let right_vec = ris.v4.more_specific(*prefix).map(|item| {
                item[0].prefix
            }).collect::<Vec<_>>();
            assert_eq!(left_vec, right_vec);
        }
        */
    }
}

