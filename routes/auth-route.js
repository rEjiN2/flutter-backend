const express = require('express');
const { authController } = require('../controllers');
const authMiddleware = require('../middlewares/auth-middleware');
const router = express.Router();

router.post("/register", authController.register);
router.post("/login", authController.login);
router.post("/refresh-token", authController.refreshAccessToken);
router.get("/logout", authMiddleware, authController.logout);
router.get("/logout-all", authMiddleware, authController.logoutAll);

module.exports = router;