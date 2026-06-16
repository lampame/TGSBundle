const path = require("path");
const webpack = require("webpack");

module.exports = {
  target: ["web"],
  entry: path.resolve(__dirname, "entry.js"),
  resolve: {
    extensions: [".js", ".json"],
    fallback: {
      fs: false,
      path: require.resolve("path-browserify"),
      net: false,
      crypto: require.resolve("telegram/crypto/crypto.js"),
      os: require.resolve("os-browserify/browser"),
      util: require.resolve("util/"),
      assert: false,
      stream: false,
      events: false,
      constants: false,
    },
  },
  mode: "production",
  plugins: [
    new webpack.ProvidePlugin({
      Buffer: ["buffer", "Buffer"],
    }),
    new webpack.ProvidePlugin({
      process: "process/browser",
    }),
  ],
  output: {
    library: "telegram",
    libraryTarget: "umd",
    filename: "telegram.js",
    path: __dirname,
  },
};
