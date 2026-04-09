const { defineConfig } = require('cypress')
const { execSync } = require('child_process')

// Snap-installed browsers live at real paths that Cypress can't auto-detect
// because /usr/bin/firefox and /usr/bin/chromium are shell wrapper scripts.
// Register them explicitly so `--browser firefox` and `--browser chromium` work.
function snapBrowsers() {
  const candidates = [
    {
      name: 'firefox',
      family: 'firefox',
      channel: 'stable',
      displayName: 'Firefox (snap)',
      // Use the /usr/bin/firefox wrapper, not the internal snap binary, so
      // the snap network environment is set up and Cypress can reach its proxy.
      path: '/usr/bin/firefox',
      versionFlag: '--version',
      versionPattern: /Firefox ([\d.]+)/,
    },
    {
      name: 'chromium',
      family: 'chromium',
      channel: 'stable',
      displayName: 'Chromium (snap)',
      path: '/snap/chromium/current/usr/lib/chromium-browser/chrome',
      versionFlag: '--version',
      versionPattern: /Chromium ([\d.]+)/,
    },
  ]

  const browsers = []
  for (const b of candidates) {
    try {
      const out = execSync(`"${b.path}" ${b.versionFlag} 2>/dev/null`, { timeout: 5000 }).toString()
      const match = out.match(b.versionPattern)
      if (match) {
        const version = match[1]
        browsers.push({
          name: b.name,
          family: b.family,
          channel: b.channel,
          displayName: b.displayName,
          path: b.path,
          version,
          majorVersion: parseInt(version.split('.')[0], 10),
        })
      }
    } catch {
      // browser not available at that path — skip
    }
  }
  return browsers
}

module.exports = defineConfig({
  e2e: {
    baseUrl: 'http://localhost:8080',
    specPattern: 'cypress/e2e/**/*.cy.js',
    video: false,
    screenshotOnRunFailure: true,
    setupNodeEvents(on, config) {
      // Register snap browsers that Cypress can't auto-detect.
      config.browsers = config.browsers.concat(snapBrowsers())

      // Required on Linux: Chromium's sandbox is incompatible with many
      // desktop environments and CI runners without elevated privileges.
      on('before:browser:launch', (browser, launchOptions) => {
        if (browser.family === 'chromium') {
          launchOptions.args.push('--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--use-gl=swiftshader')
        }
        return launchOptions
      })

      return config
    },
  },
})
