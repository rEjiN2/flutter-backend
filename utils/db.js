const mongoose = require("mongoose");

async function connectToMongoDB() {
  try {
    await mongoose.connect(process.env.MONGO, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("Connected to MongoDB");
    return true;
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
    return false;
  }
}

module.exports = { connectToMongoDB };
