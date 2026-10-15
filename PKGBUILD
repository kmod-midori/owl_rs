# SPDX-License-Identifier: GPL-3.0-or-later
pkgname=owl_rs-git
pkgver=0.1.0
pkgrel=1
pkgdesc='Linux AirDrop client and daemons with a native AWDL implementation'
arch=('x86_64' 'aarch64')
url='https://github.com/kmod-midori/owl_rs'
license=('GPL-3.0-or-later' 'MIT')
depends=('glibc' 'gcc-libs' 'dbus' 'libpcap' 'openssl' 'gtk3' 'libayatana-appindicator' 'bluez' 'networkmanager')
makedepends=('cargo' 'git' 'pkgconf')
optdepends=('gnome-shell-extension-appindicator: tray support in GNOME')
provides=("owl_rs=${pkgver}")
conflicts=('owl_rs')
source=("owl_rs::git+${url}.git")
sha256sums=('SKIP')

pkgver() {
    cd "${srcdir}/owl_rs"
    local version
    version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)
    printf '%s.r%s.g%s' "$version" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

prepare() {
    cd "${srcdir}/owl_rs"
    cargo fetch --locked
}

build() {
    cd "${srcdir}/owl_rs"
    cargo build --workspace --release --frozen --target-dir target
}

check() {
    cd "${srcdir}/owl_rs"
    cargo test --workspace --frozen --target-dir target
}

package() {
    cd "${srcdir}/owl_rs"
    install -Dm755 target/release/{owld,airdropd,catdrop} -t "${pkgdir}/usr/bin/"
    install -Dm644 README.md profiles.toml -t "${pkgdir}/usr/share/doc/owl_rs/"
    install -Dm644 docs/*.md -t "${pkgdir}/usr/share/doc/owl_rs/docs/"
    install -Dm644 COPYING -t "${pkgdir}/usr/share/licenses/${pkgname}/"
    install -Dm644 assets/apple-ca/LICENSE.omdrop-plugin -t "${pkgdir}/usr/share/licenses/${pkgname}/"

    install -dm755 "${pkgdir}/usr/lib/systemd/"{system,user}
    sed -e '/^# Replace the build path/d' \
        -e 's|/path/to/owl_rs/target/release/|/usr/bin/|g' \
        -e 's/--user USER/--user %i/' examples/owld.service \
        > "${pkgdir}/usr/lib/systemd/system/owld@.service"
    sed -e '/^# Run with systemctl/d' \
        -e 's|/path/to/owl_rs/target/release/|/usr/bin/|g' examples/airdropd.service \
        > "${pkgdir}/usr/lib/systemd/user/airdropd.service"
}
