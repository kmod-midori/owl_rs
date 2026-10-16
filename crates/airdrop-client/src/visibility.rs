// SPDX-License-Identifier: GPL-3.0-or-later
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Visibility {
    Everyone,
    Contacts,
    #[default]
    Off,
}
impl Visibility {
    pub fn enabled(self) -> bool {
        self != Self::Off
    }
}
