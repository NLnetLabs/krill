let username = 'admin@krill';

describe('OpenID Connect provider with OAuth 2 revocation', () => {
  it('Logout when logged in behaves as expected', () => {
    cy.visit('/')
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]').clear().type(username)
    cy.contains('Sign In').click()

    // We should end up back in the Krill UI
    cy.url().should('include', Cypress.config('baseUrl'))
    cy.contains('Sign In').should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(username)
    cy.get('#userinfo_table').contains("role")

    // logout
    cy.intercept('GET', /^http:\/\/localhost:1818\/revoke.+/).as('oauth2revoke')
    cy.get('.logout').click()
    cy.wait('@oauth2revoke').its('response.statusCode').should('eq', 302)

    // verify that we are shown the OpenID Connect provider login page
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]')
  })
})