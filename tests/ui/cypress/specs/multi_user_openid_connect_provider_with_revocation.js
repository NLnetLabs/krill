let username = 'shorttokenwithrefresh@krill';

// TODO: test revocation of both access and refresh tokens?
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

    // verify that the mock provider thinks the user is logged in
    cy.request('http://127.0.0.1:1818/control/is_user_logged_in?username=' + username).its('status').should('eq', 200)

    // logout
    cy.get('.logout').click()

    // verify that we are shown the OpenID Connect provider login page
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]')

    // verify that the mock provider thinks the user is now logged out
    cy.request({ url: 'http://127.0.0.1:1818/control/is_user_logged_in?username=' + username, failOnStatusCode: false }).its('status').should('eq', 400)
  })
})