// I considered using enumflags2 instead but it doesn't permit flags with more
// than one bit set which precludes easily making a constant for a group of set
// flags without having a very | long | combined | set of permissions assigned
// to the constant. For a much heavier more complicated but more flexible
// approach we could use something like the Rust casbin or oso crates.
bitflags! {
    pub struct Permissions: u32 {
        const NONE              = 00000000000000000000;

        // LOGIN is the minimum possible permission, without this you won't be
        // able to do anything even if you otherwise authenticated correctly.
        const LOGIN             = 0b000000000000000001;

        // Working with Certificate Authorities
        const CA_LIST           = 0b000000000000000010;
        const CA_READ           = 0b000000000000000100;
        const CA_CREATE         = 0b000000000000001000;
        const CA_UPDATE         = 0b000000000000010000;
        const CA_ADMIN          = 0b000000000000011110;

        // Working with Publishers
        const PUB_LIST          = 0b000000000000100000;
        const PUB_READ          = 0b000000000001000000;
        const PUB_CREATE        = 0b000000000010000000;
        const PUB_UPDATE        = 0b000000000100000000;
        const PUB_DELETE        = 0b000000001000000000;
        const PUB_ADMIN         = 0b000000001111100000;

        // Working with Routes
        const ROUTES_READ       = 0b000000010000000000;
        const ROUTES_UPDATE     = 0b000000100000000000;
        const ROUTES_TRY_UPDATE = 0b000001000000000000;
        const ROUTES_ANALYSIS   = 0b000010000000000000;
        const ROUTES_ADMIN      = 0b000011110000000000;

        // Working with Resource Tagged Attestations
        const RTA_LIST          = 0b000100000000000000;
        const RTA_READ          = 0b001000000000000000;
        const RTA_CREATE        = 0b010000000000000000;
        const RTA_UPDATE        = 0b100000000000000000;
        const RTA_ADMIN         = 0b111100000000000000;

        // "GUI" permissons relate to actions that can be taken via the Krill
        // UI and as such are a subset of the total possible set of permissions,
        // e.g. it is possible to do more via krillc than via the UI, and
        // possibly even more via the REST API directly than via krillc.
        // Assigning GUI permissions is a way of ensuring that the assigned
        // permissions don't exceed what is possible via the UI.
        const GUI_READ          = Self::LOGIN.bits | Self::CA_LIST.bits | Self::CA_READ.bits | Self::PUB_LIST.bits | Self::PUB_READ.bits | Self::ROUTES_READ.bits | Self::ROUTES_ANALYSIS.bits;
        const GUI_WRITE         = Self::LOGIN.bits | Self::CA_ADMIN.bits | Self::PUB_ADMIN.bits | Self::ROUTES_ADMIN.bits;
        const GUI_ADMIN         = Self::GUI_WRITE.bits;

        const ALL_ADMIN         = Self::GUI_ADMIN.bits | Self::RTA_ADMIN.bits;

        const TESTBED           = Self::CA_READ.bits | Self::CA_UPDATE.bits | Self::PUB_ADMIN.bits;
    }
}