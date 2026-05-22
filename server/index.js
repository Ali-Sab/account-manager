"use strict";

const { app } = require("./app");

const PORT = parseInt(process.env.PORT || "3001", 10);

app.listen(PORT, () => {
  console.log(`[account-manager] Listening on port ${PORT}`);
});
