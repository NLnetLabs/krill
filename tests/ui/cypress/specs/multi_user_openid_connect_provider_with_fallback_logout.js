let username = 'admin@krill';

describe('OpenID Connect provider with fallback logout URL', () => {
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

    // verify that the mock provider thinks the user is logged in
    cy.request('http://127.0.0.1:1818/test/is_user_logged_in?username=' + username).its('status').should('eq', 200)

    // logout
    cy.intercept('/auth/logout').as('getLogoutURL')
    cy.get('.logout').click()

    // verify that we are shown the OpenID Connect provider login page
    cy.wait('@getLogoutURL').its('response.statusCode').should('eq', 200)
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]')

    // verify that the mock provider thinks the user is STILL logged in because due to the OpenID Connect mock being
    // configured to NOT support end_session_endpoint or revocation_endpoint there is no way to tell the mock that we
    // are logging the user out
    cy.request('http://127.0.0.1:1818/test/is_user_logged_in?username=' + username).its('status').should('eq', 200)
  })
})