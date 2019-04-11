module.exports = {
  devServer: {
    proxy: 'http://localhost:3000'
  },

  publicPath: '/ui',

  pluginOptions: {
    i18n: {
      locale: 'en',
      fallbackLocale: 'en',
      localeDir: 'locales',
      enableInSFC: false
    }
  }
}
