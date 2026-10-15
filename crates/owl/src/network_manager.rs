// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded NetworkManager operations over the system bus.
use anyhow::{Context, Result, bail};
use std::{future::Future, time::Duration};
use zbus::{Connection, Proxy, proxy::CacheProperties, zvariant::OwnedObjectPath};

const SERVICE: &str = "org.freedesktop.NetworkManager";
const ROOT: &str = "/org/freedesktop/NetworkManager";
const DEVICE: &str = "org.freedesktop.NetworkManager.Device";
const ACTIVE: &str = "org.freedesktop.NetworkManager.Connection.Active";

async fn bounded<T>(timeout: Duration, operation: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(timeout, operation)
        .await
        .context("NetworkManager D-Bus operation timed out")?
}

async fn proxy<'a>(bus: &'a Connection, path: &'a str, interface: &'a str) -> Result<Proxy<'a>> {
    // State polls must read the service, not a proxy's property cache.
    Ok(zbus::proxy::Builder::new(bus)
        .destination(SERVICE)?
        .path(path)?
        .interface(interface)?
        .cache_properties(CacheProperties::No)
        .build()
        .await?)
}

pub(crate) struct Device {
    bus: Connection,
    path: OwnedObjectPath,
    timeout: Duration,
}

impl Device {
    pub(crate) async fn open(interface: &str, timeout: Duration) -> Result<Self> {
        bounded(timeout, async {
            let bus = Connection::system().await?;
            let path = proxy(&bus, ROOT, SERVICE)
                .await?
                .call("GetDeviceByIpIface", &(interface,))
                .await
                .with_context(|| format!("NetworkManager device {interface}"))?;
            Ok(Self { bus, path, timeout })
        })
        .await
    }

    async fn proxy(&self) -> Result<Proxy<'_>> {
        proxy(&self.bus, self.path.as_str(), DEVICE).await
    }

    pub(crate) async fn set_managed(&self, managed: bool) -> Result<()> {
        bounded(self.timeout, async {
            // The writable property also supports NetworkManager before 1.58.
            self.proxy().await?.set_property("Managed", managed).await?;
            Ok(())
        })
        .await
    }

    pub(crate) async fn is_unmanaged(&self) -> Result<bool> {
        bounded(self.timeout, async {
            // NM_DEVICE_STATE_UNMANAGED
            Ok(self.proxy().await?.get_property::<u32>("State").await? == 10)
        })
        .await
    }
}

pub(crate) async fn snapshot(interface: &str, timeout: Duration) -> Result<(bool, Option<String>)> {
    bounded(timeout, async {
        let device = Device::open(interface, timeout).await?;
        let properties = device.proxy().await?;
        let managed = properties.get_property("Managed").await?;
        let active: OwnedObjectPath = properties.get_property("ActiveConnection").await?;
        let uuid = if active.as_str() == "/" {
            None
        } else {
            Some(
                proxy(&device.bus, active.as_str(), ACTIVE)
                    .await?
                    .get_property("Uuid")
                    .await?,
            )
        };
        Ok((managed, uuid))
    })
    .await
}

pub(crate) async fn set_managed(interface: &str, managed: bool, timeout: Duration) -> Result<()> {
    bounded(timeout, async {
        Device::open(interface, timeout)
            .await?
            .set_managed(managed)
            .await
    })
    .await
}

pub(crate) async fn reconnect(
    interface: &str,
    uuid: &str,
    timeout: Duration,
    wait: Duration,
) -> Result<()> {
    bounded(timeout, async {
        let device = Device::open(interface, timeout).await?;
        let settings = proxy(
            &device.bus,
            "/org/freedesktop/NetworkManager/Settings",
            "org.freedesktop.NetworkManager.Settings",
        )
        .await?;
        let connection: OwnedObjectPath = settings.call("GetConnectionByUuid", &(uuid,)).await?;
        let root = OwnedObjectPath::try_from("/")?;
        let active: OwnedObjectPath = proxy(&device.bus, ROOT, SERVICE)
            .await?
            .call("ActivateConnection", &(connection, &device.path, root))
            .await?;
        let active = proxy(&device.bus, active.as_str(), ACTIVE).await?;
        bounded(wait, async {
            loop {
                match active.get_property::<u32>("State").await? {
                    2 => return Ok(()), // NM_ACTIVE_CONNECTION_STATE_ACTIVATED
                    3 | 4 => {
                        bail!("NetworkManager connection {uuid} deactivated during restoration")
                    }
                    _ => tokio::time::sleep(Duration::from_millis(50)).await,
                }
            }
        })
        .await
    })
    .await
    .with_context(|| format!("restoring NetworkManager connection {uuid} on {interface}"))
}
