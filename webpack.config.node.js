const webpack = require('webpack');
const path = require('path');
const fs = require('fs');

const nodeModules = {};
fs.readdirSync('node_modules')
  .filter(x => ['.bin'].indexOf(x) === -1)
  .forEach((mod) => {
    nodeModules[mod] = `commonjs ${mod}`;
  });

module.exports = {
  devtool: 'eval-source-map',
  target: 'node',
  entry: [
    'whatwg-fetch',
    path.join(__dirname, 'src', 'index.node.js'),
  ],
  output: {
    libraryTarget: 'umd',
    library: 'tidepay',
    path: path.join(__dirname, 'build'),
    filename: 'index.js',
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            cacheDirectory: 'babel_cache',
          },
        },
      }, {
        test: /\.json$/,
        loader: 'json-loader',
      },
    ],
  },
  externals: nodeModules,
  plugins: [
    new webpack.DefinePlugin({
      'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV),
    }),
    new webpack.optimize.OccurrenceOrderPlugin(),
    new webpack.optimize.UglifyJsPlugin({
      compress: { warnings: false },
      mangle: true,
      sourceMap: true,
      beautify: false,
    }),
  ],
};
