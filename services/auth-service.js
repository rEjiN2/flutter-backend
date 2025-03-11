const { User } = require("../models/Users");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const {
  sanitizeObject,
  isValidEmail,
  isStrongPassword,
} = require("../utils/validation");

// Generate access token
const generateAccessToken = (userId) => {
  return jwt.sign(
    { userId },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: "15m" } // Short-lived token
  );
};

// Generate refresh token
const generateRefreshToken = (userId) => {
  // Create a unique token ID for revocation purposes
  const tokenId = crypto.randomBytes(16).toString("hex");

  return {
    token: jwt.sign(
      { userId, tokenId },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" } // Long-lived token
    ),
    tokenId,
  };
};

const register = async (data) => {
  // Sanitize input data
  const sanitizedData = sanitizeObject(data);
  const { username, email, password } = data;
  try {
    // Additional validation
    if (!username || !email || !password) {
      return {
        status: false,
        message: "Username, email and password are required",
      };
    }

    if (!isValidEmail(email)) {
      return {
        status: false,
        message: "Invalid email format",
      };
    }

    if (!isStrongPassword(password)) {
      return {
        status: false,
        message:
          "Password must be at least 6 characters and contain at least one letter and one number",
      };
    }

    let existingUser = await User.findOne({
      $or: [{ email }, { username }],
    });

    if (existingUser) {
      return {
        status: false,
        message: "User already exists with this email or username",
      };
    }

    // Create user without tokens first
    const user = new User({
      username,
      email,
      password,
      refreshTokens: [], // Array to store active refresh token IDs
    });

    // Generate tokens
    const accessToken = generateAccessToken(user._id);
    const { token: refreshToken, tokenId } = generateRefreshToken(user._id);

    // Store tokens
    user.refreshTokens.push(tokenId); // Store token ID for validation

    await user.save();

    return {
      status: true,
      data: {
        userId: user._id,
        username: user.username,
        email: user.email,
        accessToken,
        refreshToken,
      },
      message: "User registered successfully",
    };
  } catch (error) {
    return {
      status: false,
      message: error.message,
    };
  }
};

const login = async (data) => {
  const sanitizedData = sanitizeObject(data);
  const { email, password } = data;
  try {
    // Validate inputs
    if (!email || !password) {
      return {
        status: false,
        message: "Email and password are required",
      };
    }

    if (!isValidEmail(email)) {
      return {
        status: false,
        message: "Invalid email format",
      };
    }

    const user = await User.findOne({ email });

    if (!user) {
      return {
        status: false,
        message: "Invalid credentials",
      };
    }

    // Check password
    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      return {
        status: false,
        message: "Invalid credentials",
      };
    }

    // Generate tokens
    const accessToken = generateAccessToken(user._id);
    const { token: refreshToken, tokenId } = generateRefreshToken(user._id);

    // Store refresh token ID
    user.refreshTokens.push(tokenId);

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    return {
      status: true,
      data: {
        userId: user._id,
        username: user.username,
        email: user.email,
        accessToken,
        refreshToken,
      },
      message: "Login successful",
    };
  } catch (error) {
    return {
      status: false,
      message: error.message,
    };
  }
};

const refreshToken = async (refreshToken) => {
  try {
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const { userId, tokenId } = decoded;

    // Find user and check if refresh token is valid
    const user = await User.findById(userId);

    if (!user || !user.refreshTokens.includes(tokenId)) {
      return {
        status: false,
        message: "Invalid refresh token",
      };
    }

    // Generate new tokens
    const newAccessToken = generateAccessToken(userId);
    const newRefreshTokenObj = generateRefreshToken(userId);

    // Remove old refresh token and add new one
    user.refreshTokens = user.refreshTokens.filter((id) => id !== tokenId);
    user.refreshTokens.push(newRefreshTokenObj.tokenId);

    await user.save();

    return {
      status: true,
      data: {
        accessToken: newAccessToken,
        refreshToken: newRefreshTokenObj.token,
      },
      message: "Token refreshed successfully",
    };
  } catch (error) {
    return {
      status: false,
      message:
        error.name === "TokenExpiredError"
          ? "Refresh token expired"
          : "Invalid refresh token",
    };
  }
};

const logout = async (userId, refreshToken) => {
  try {
    // Verify refresh token to get the token ID
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const { tokenId } = decoded;

    // Remove the specific refresh token
    await User.findByIdAndUpdate(userId, {
      $pull: { refreshTokens: tokenId },
    });

    return {
      status: true,
      message: "Logout successful",
    };
  } catch (error) {
    return {
      status: false,
      message: error.message,
    };
  }
};

const logoutAll = async (userId) => {
  try {
    // Remove all refresh tokens for the user
    await User.findByIdAndUpdate(userId, {
      $set: { refreshTokens: [] },
    });

    return {
      status: true,
      message: "All sessions logged out successfully",
    };
  } catch (error) {
    return {
      status: false,
      message: error.message,
    };
  }
};

module.exports = {
  register,
  login,
  refreshToken,
  logout,
  logoutAll,
};
