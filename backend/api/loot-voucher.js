// backend/api/loot-voucher.js
// Retired. Voucher issuance moved to /api/claim-voucher (SIWS + Redis nonce).
// This mount only tells old clients where to go. It does not sign anything.
const router = require("express").Router();

router.all("*", (_req, res) => {
  res.status(410).json({
    ok: false,
    error: "moved",
    location: "/api/claim-voucher",
  });
});

module.exports = router;
