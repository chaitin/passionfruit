const path = require('path')
const webpack = require('webpack')
const UglifyJsPlugin = require('uglifyjs-webpack-plugin')
const CopyWebpackPlugin = require('copy-webpack-plugin')
const WriteFilePlugin = require('write-file-webpack-plugin')


module.exports = {
  entry: path.resolve(__dirname, './src/main.js'),
  output: {
    path: path.resolve(__dirname, './static'),
    publicPath: '/static/',
    filename: 'build.js'
  },
  module: {
    rules: [{
      test: /\.vue$/,
      loader: 'vue-loader',
      options: {
        loaders: {

        }
      }
    },
    {
      test: /\.scss$/,
      use: ['style-loader', 'css-loader', 'sass-loader']
    },
    {
      test: /\.css$/,
      use: ['style-loader', 'css-loader']
    },
    {
      test: /\.js$/,
      exclude: /node_modules/,
      use: {
        loader: 'babel-loader',
        options: {
          presets: ['@babel/preset-env']
        }
      }
    },
    {
      test: /\.(d\.ts|txt)$/,
      loader: 'raw-loader',
    },
    {
      test: /\.(png|jpg|gif|svg|eot|svg|ttf|woff|woff2)$/,
      loader: 'file-loader',
      options: {
        name: '[name].[ext]?[hash]'
      }
    }]
  },
  resolve: {
    alias: {
      'vue$': 'vue/dist/vue.esm.js',
      '~': path.resolve(__dirname, 'src'),
    },
  },
  devServer: {
    historyApiFallback: {
      rewrites: [{
        from: /^\/app\/.*$/,
        to: function () {
          return 'index.html'
        }
      },
      {
        from: /^\/welcome\/.*$/,
        to: function () {
          return 'index.html'
        }
      },
      {
        from: /^\/url\/.*$/,
        to: function () {
          return 'index.html'
        }
      }]
    },
    noInfo: true,
    proxy: {
      '/api': {
        target: 'http://localhost:31337',
        secure: false
      },
      '/msg': {
        target: 'http://localhost:31337',
        secure: false
      }
    }
  },
  performance: {
    hints: false
  },
  devtool: '#eval-source-map'
}

const plugins = module.exports.plugins = [
  new WriteFilePlugin(),
  new CopyWebpackPlugin([
    {
      from: path.join(__dirname, 'node_modules', 'monaco-editor', 'min', 'vs'),
      to: 'vs'
    },
    {
      from: path.join(__dirname, 'src', 'assets', 'icon.svg'),
      to: 'icon.svg'
    }
  ]),
]

if (process.env.NODE_ENV === 'production') {
  module.exports.devtool = '#source-map'
  // http://vue-loader.vuejs.org/en/workflow/production.html
  module.exports.plugins = plugins.concat([
    new webpack.DefinePlugin({
      'process.env': {
        NODE_ENV: '"production"'
      }
    }),
    new UglifyJsPlugin({
      uglifyOptions: {
        ie8: false,
        ecma: 8,
        output: { comments: false },
        compress: { unused: true, dead_code: true, warnings: false }
      },
      sourceMap: true,
    }),
    new webpack.LoaderOptionsPlugin({
      minimize: true
    }),
  ])
}
