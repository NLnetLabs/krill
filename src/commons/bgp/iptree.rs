use std::collections::HashMap;
use std::ops::Range;

use intervaltree::IntervalTree;

use crate::commons::api::TypedPrefix;

//------------ IpRange -----------------------------------------------------

struct IpRange(Range<u128>);

impl IpRange {
    fn contains(&self, other: &Range<u128>) -> bool {
        self.0.start <= other.start && self.0.end >= other.end
    }

    fn is_contained_by(&self, other: &Range<u128>) -> bool {
        other.start <= self.0.start && other.end >= self.0.end
    }
}

impl From<&TypedPrefix> for IpRange {
    fn from(tp: &TypedPrefix) -> Self {
        match tp {
            TypedPrefix::V4(pfx) => {
                let (min, max) = pfx.as_ref().range();
                let start = min.to_v4().to_ipv6_mapped().into();
                let end = max.to_v4().to_ipv6_mapped().into();
                IpRange(Range { start, end })
            }
            TypedPrefix::V6(pfx) => {
                let (min, max) = pfx.as_ref().range();
                let start = min.to_v6().into();
                let end = max.to_v6().into();
                IpRange(Range { start, end })
            }
        }
    }
}

//------------ TypedPrefixTree ---------------------------------------------

pub struct TypedPrefixTree<V: AsRef<TypedPrefix>> {
    tree: IntervalTree<u128, Vec<V>>,
}

impl<V: AsRef<TypedPrefix>> TypedPrefixTree<V> {
    pub fn matching_or_more_specific(&self, pfx: &TypedPrefix) -> Vec<&V> {
        let mut res = vec![];
        let range = IpRange::from(pfx);
        for el in self.tree.query(range.0.clone()) {
            if range.contains(&el.range) {
                for v in &el.value {
                    res.push(v)
                }
            }
        }
        res
    }

    pub fn matching_or_less_specific(&self, pfx: &TypedPrefix) -> Vec<&V> {
        let mut res = vec![];
        let range = IpRange::from(pfx);
        for el in self.tree.query(range.0.clone()) {
            if range.is_contained_by(&el.range) {
                for v in &el.value {
                    res.push(v)
                }
            }
        }
        res
    }
}

//------------ TypedPrefixTreeBuilder --------------------------------------

pub struct TypedPrefixTreeBuilder<V: AsRef<TypedPrefix>> {
    values: HashMap<Range<u128>, Vec<V>>,
}

impl<V: AsRef<TypedPrefix>> TypedPrefixTreeBuilder<V> {
    pub fn add(&mut self, value: V) {
        let range = IpRange::from(value.as_ref()).0;
        let entry = self.values.entry(range).or_insert_with(|| vec![]);
        entry.push(value);
    }

    pub fn build(self) -> TypedPrefixTree<V> {
        let tree = self.values.into_iter().collect();
        TypedPrefixTree { tree }
    }
}

impl<V: AsRef<TypedPrefix>> Default for TypedPrefixTreeBuilder<V> {
    fn default() -> Self {
        TypedPrefixTreeBuilder {
            values: HashMap::new(),
        }
    }
}

//------------ Tests --------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commons::bgp::Announcement;
    use std::str::FromStr;

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
        assert_eq!(3, tree.matching_or_more_specific(&search).len());

        let search = TypedPrefix::from_str("10.0.2.0/24").unwrap();
        assert_eq!(0, tree.matching_or_more_specific(&search).len());
    }

    #[test]
    fn typed_prefix_tree_less_specific() {
        let tree = make_test_tree();
        let search = TypedPrefix::from_str("10.0.0.0/23").unwrap();
        assert_eq!(3, tree.matching_or_less_specific(&search).len());

        let search = TypedPrefix::from_str("10.0.0.0/24").unwrap();
        assert_eq!(4, tree.matching_or_less_specific(&search).len());

        let search = TypedPrefix::from_str("10.0.0.0/16").unwrap();
        assert_eq!(1, tree.matching_or_less_specific(&search).len());

        let search = TypedPrefix::from_str("10.0.0.0/15").unwrap();
        assert_eq!(0, tree.matching_or_less_specific(&search).len());
    }
}
