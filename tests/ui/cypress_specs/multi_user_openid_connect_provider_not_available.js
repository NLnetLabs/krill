describe('OpenID Connect users', () => {
  it('The correct login form is shown', () => {
    cy.intercept('GET', '/api/v1/authorized').as('isAuthorized')
    cy.intercept('GET', '/auth/login').as('getLoginURL')
    cy.intercept('GET', /^http:\/\/localhost:1818\/authorize.+/).as('oidcLoginForm')
    cy.visit('/')
    cy.wait(['@isAuthorized', '@getLoginURL', '@oidcLoginForm'])

    // // make sure we haven't been redirected away from Krill (as would be the
    // // case if an OpenID Connect login form were shown)
    // cy.url().should('not.include', Cypress.config('baseUrl'))

    // // make sure that this is our mock OpenID Connect provider
    // cy.contains('Mock OpenID Connect login form')

    // // check that a username input field is shown on the page
    // cy.get('input[name="username"]')
  })
})