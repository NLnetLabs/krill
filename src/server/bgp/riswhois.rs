//! The data from a RISwhois data set.
//!
//! These datasets provide the originating AS numbers for address prefixes
//! as encountered in BGP data collected by RIS. The [`RisWhois`] type in
//! this module collects all this data and makes it available for querying.

// This code only works with `usize` of at least 32 bits.
#[cfg(target_pointer_width = "16")]
compile_error!("cannot build on 16 bit systems");

use std::{cmp, error, fmt, io};
use std::io::BufReader;
use std::str::FromStr;
use libflate::gzip;
use crate::api::roa::{AsNumber, Ipv4Prefix, Ipv6Prefix, TypedPrefix};
use crate::api::bgp::Announcement;


//------------ Configuration -------------------------------------------------

/// How often to we need to see a route origin before accepting it.
///
/// For each pair of address prefix and origin AS number, RISwhois also lists
/// how many of the peers of RIS have seen this pair in their BGP streams.
/// Pairs that are only seen by very few peers are likely there by mistake
/// and should be filtered out. This constant sets the minimum number of
/// stream that have to have seen a pair for us to include it in our data.
///
/// This number was at some point recommended by RIS.
const MINIMUM_SEEN_BY: u32 = 13;


//------------ RisWhoisLoader ------------------------------------------------

/// A type that knows where RISwhois data lives and download it.
pub struct RisWhoisLoader {
    /// The HTTP(S) URL of the location of IPv4 data set.
    v4_url: String,

    /// The HTTP(S) URL of the location of IPv6 data set.
    v6_url: String,
}

impl RisWhoisLoader {
    /// Creates a new loader from the URLS of the IPv4 and IPv6 data sets.
    pub fn new(v4_url: String, v6_url: String) -> Self {
        Self { v4_url, v6_url }
    }

    /// Downloads and processes a new data set.
    pub async fn load(&self) -> Result<RisWhois, RisWhoisError> {
        Ok(RisWhois::new(
            Self::load_tree(&self.v4_url).await?,
            Self::load_tree(&self.v6_url).await?,
        ))
    }

    /// Downloads and process the tree for one address family.
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

    /// Parses the gzipped data.
    fn parse_gz_data<P: FromStr + RoutePrefix>(
        data: &[u8]
    ) -> Result<RouteOriginCollection<P>, io::Error>
    where <P as FromStr>::Err: error::Error + Send + Sync + 'static {
        let data = BufReader::new(
            gzip::Decoder::new(data)?
        );
        Self::parse_data(data)
    }

    /// Parses the raw data.
    pub(super) fn parse_data<P: FromStr + RoutePrefix>(
        data: impl io::BufRead,
    ) -> Result<RouteOriginCollection<P>, io::Error>
    where <P as FromStr>::Err: error::Error + Send + Sync + 'static {
        let mut res = Vec::new();
        for line in data.lines() {
            // Each line is as follows:
            //
            //    o  empty lines and lines starting with % are ignored.
            //    o  all other lines consist of three string separated by
            //       white space (technically: a single HTAB):
            //
            //          o  origin AS number as an integer,
            //          o  prefix as IP address slash prefix length,
            //          o  number of peers that have seen this pair.
            //
            //       Instead of the origin AS number, there may be an AS set
            //       as a sequence of comma separated AS numbers surrounded by
            //       curly braces. We ignore those.
            //
            //       If the number of peers that have seen a pair is smaller
            //       than `MINIMUM_SEEN_BY`, the line is also ignored.

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

            if u32::from_str(peers).map_err(io::Error::other)?
                < MINIMUM_SEEN_BY
            {
                continue;
            }

            if asn_str.contains('{') {
                continue; // assets not supported (not important here either)
            }

            let origin = AsNumber::from_str(asn_str).map_err(io::Error::other)?;
            let prefix = P::from_str(prefix_str).map_err(|err| {
                io::Error::other(err)
            })?;

            res.push(RouteOrigin { prefix, origin });
        }

        Ok(RouteOriginCollection::new(res).unwrap())
    }
}


//------------ RisWhois ------------------------------------------------------

/// A set of RISwhois data.
///
/// This data consists of two route origin collections, one for IPv4 and one
/// for IPv6.
#[derive(Clone, Default)]
pub struct RisWhois {
    /// The IPv4 route origin collection.
    v4: RouteOriginCollection<Ipv4Prefix>,

    /// The IPv6 route origin collection.
    v6: RouteOriginCollection<Ipv6Prefix>,
}

impl RisWhois {
    /// Creates a new data set from the IPv4 and IPv6 data.
    pub fn new(
        v4: RouteOriginCollection<Ipv4Prefix>,
        v6: RouteOriginCollection<Ipv6Prefix>,
    ) -> Self {
        Self { v4, v6 }
    }

    /// Returns the IPv4 route origin collection.
    pub fn v4(&self) -> &RouteOriginCollection<Ipv4Prefix> {
        &self.v4
    }

    /// Returns the IPv6 route origin collection.
    pub fn v6(&self) -> &RouteOriginCollection<Ipv6Prefix> {
        &self.v6
    }
}


//------------ RouteOriginCollection -----------------------------------------

/// A collection of RISwhois route origins.
///
/// This type keeps the route origins for the prefix type `P`, which can be
/// [`Ipv4Prefix`] or [`Ipv6Prefix`]. It is read-only, allowing to iterate
/// over part of the data.
///
/// It currently only supports iterating over the more specifics of a given
/// prefix since that is all we need for the BGP analyser.
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

/// A set of route origins.
///
/// This is a thin wrapper around a non-empty slice of [`RouteOrigin<P>']
/// with the same prefix, allowing access to the prefix with unwrapping and
/// such.
#[derive(Clone, Copy, Debug)]
pub struct RouteOriginSet<'a, P> {
    /// The underlying slice.
    slice: &'a [RouteOrigin<P>],
}

impl<'a, P: RoutePrefix> RouteOriginSet<'a, P> {
    /// Creates a new value from a non-empty slice.
    fn new(slice: &'a [RouteOrigin<P>]) -> Self {
        debug_assert!(!slice.is_empty());
        Self { slice }
    }

    /// Returns the prefix of the set.
    pub fn prefix(self) -> P {
        // Safety: self.slice is not empty.
        self.slice[0].prefix
    }

    /// Returns an iterator over the individual route origins of the set.
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
    #[cfg(test)]
    fn new(collection: &'a RouteOriginCollection<P>) -> Self {
        Self {
            collection,
            tree_idx_stack: match collection.tree_root_idx.into_usize() {
                Some(idx) => vec![idx],
                None => Vec::new()
            }
        }
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
        let v4 = RisWhoisLoader::parse_data(include_bytes!(
            "../../../test-resources/bgp/riswhoisdump.IPv4"
        ).as_ref()).unwrap();
        let v6 = RisWhoisLoader::parse_data(include_bytes!(
            "../../../test-resources/bgp/riswhoisdump.IPv6"
        ).as_ref()).unwrap();
        let ris = RisWhois { v4, v6 };

        let v4 = TreeIter::new(&ris.v4).map(|item| {
            for origin in item.iter() {
                assert_eq!(origin.prefix, item.prefix());
            }
            item.prefix()
        }).collect::<Vec<_>>();
        for item in v4.windows(2) {
            assert!(item[0] < item[1])
        }
        let v6 = TreeIter::new(&ris.v6).map(|item| {
            for origin in item.iter() {
                assert_eq!(origin.prefix, item.prefix());
            }
            item.prefix()
        }).collect::<Vec<_>>();
        for item in v6.windows(2) {
            assert!(item[0] < item[1])
        }
    }
}

