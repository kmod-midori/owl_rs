# Apple Application Integration intermediates

Public issuing certificates for verifying AirDrop client identities:
`apple-aai-ca.pem` and `apple-aai2-ca.pem`. They supplement a peer's chain as
untrusted intermediates; only `../apple_root_ca.pem` is a trust anchor.

Copied from [omdrop-plugin](https://github.com/brentkearney/omdrop-plugin/tree/b2f9a537b150c26402c5daad8125fb7e61c214ec/bin/apple-ca).
The reference project's [MIT license notice](LICENSE.omdrop-plugin) is retained.
