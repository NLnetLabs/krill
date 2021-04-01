describe('OpenID Connect provider connection issues are tolerated', () => {
  it('The login form should not be available', () => {
    cy.request('POST', 'https://127.0.0.1:1818/test/disable')
    cy.wait(500)

    cy.visit('/')
    cy.url().should('include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form').should('not.exist')
    cy.contains('An error occurred while logging you in: OpenID Connect: Cannot get login URL: Failed to connect to provider')
  })

  it('Login and logout should succeed', () => {
    cy.request('POST', 'https://127.0.0.1:1818/test/enable')
    cy.wait(500)

    // Login
    cy.visit('/')
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]').clear().type('admin')
    cy.get('input[name="userattr1"]').clear().type('role') // a role is required to be able to login
    cy.get('input[name="userattrval1"]').clear().type('admin')
    cy.contains('Sign In').click()

    // verify that we are shown to be logged in to the Krill UI
    cy.contains('Sign In').should('not.exist')
    cy.url().should('include', Cypress.config('baseUrl'))
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains('admin')

    // verify that the mock provider thinks the user is logged in
    cy.request({ url: 'https://127.0.0.1:1818/test/is_user_logged_in?username=admin', failOnStatusCode: false }).its('status').should('eq', 200)

    // logout
    cy.intercept('GET', /^https:\/\/localhost:1818\/logout.+/).as('oidcLogout')
    cy.get('.logout').click()
    cy.wait('@oidcLogout').its('response.statusCode').should('eq', 302)

    // verify that the mock provider thinks the user is now logged out
    cy.request({ url: 'https://127.0.0.1:1818/test/is_user_logged_in?username=admin', failOnStatusCode: false }).its('status').should('eq', 400)

    // verify that we are shown the OpenID Connect provider login page
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]')
  })

  it('Login should fail to redirect to the discovered but unavailable login page', () => {
    cy.request('POST', 'https://127.0.0.1:1818/test/disable')
    cy.wait(500)
    cy.visit('/')
  })

  it('The login page should be reachable again', () => {
    cy.request('POST', 'https://127.0.0.1:1818/test/enable')
    cy.wait(500)
    cy.visit('/')
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
  })
})