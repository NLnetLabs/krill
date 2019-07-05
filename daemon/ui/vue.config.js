const webpack = require('webpack')

module.exports = {
  devServer: {
    proxy: 'https://localhost:3000'
  },

  publicPath: '/ui',

  pluginOptions: {
    i18n: {
      locale: 'en',
      fallbackLocale: 'en',
      localeDir: 'locales',
      enableInSFC: false
    }
  },

  filenameHashing: false,

  configureWebpack: {
    plugins: [
      new webpack.optimize.LimitChunkCountPlugin({
        maxChunks: 1
      })
    ]
  },
  chainWebpack: config => {
    config.optimization.delete('splitChunks')
  }

}
