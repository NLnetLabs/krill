describe('OpenID Connect users', () => {
  it('The correct login form is shown', () => {
    cy.intercept('GET', '/api/v1/authorized').as('isAuthorized')
    cy.intercept('GET', '/auth/login').as('getLoginURL')
    cy.visit('/')
    cy.wait('@isAuthorized').its('response.statusCode').should('eq', 401)
    cy.wait('@getLoginURL').its('response.statusCode').should('eq', 401) // should this be 500?

    // make sure we haven't been redirected away from Krill (as would be the
    // case if an OpenID Connect login form were shown)
    cy.url().should('include', Cypress.config('baseUrl'))

    // make sure that we are shown the correct error
    cy.contains('An error occurred while logging you in: Cannot get login URL: Failed to connect to provider')
  })
})