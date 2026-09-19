# V5 source mirror

These two NinjaTrader strategy sources are mirrored from PR #192
(`samhui6688-spec/-sam-Personal-Capital-OS`, `ninja/SamQuant/`,
commit `7e4a628fd3bb1a928ab740ccb523de262f529f67`).

SHA-256 pins (fail closed on mismatch):
- SamQuantStrategy.cs (4482 bytes): 07da03f4f4dfbb094bd35943fd37db51e83a10c8827e2add3c8f96ab26cd0652
- SamQuantRiskGuard.cs (3020 bytes): da8594d720921e04312779f4c179c465bffacd8311404389a2dde5fb93a30b98

Security does NOT rely on this mirror being trustworthy: the worker's
`download_file` checks every file against the pinned SHA-256 and drops +
fails closed on mismatch. The worker only needs a *public* URL because it
cannot authenticate to the private source repo.
