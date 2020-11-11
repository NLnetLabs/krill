describe('Config File Users', () => {
    it('The correct login form is shown', () => {
      cy.visit('/')
  
      // make sure we haven't been redirected away from Krill (as would be the
      // case if an OpenID Connect login form were shown)
      cy.url().should('not.include', Cypress.config('baseUrl'))

      // make sure that this is our mock OpenID Connect provider
      cy.contains('Mock OpenID Connect login form')

      // check that a username input field is shown on the page
      cy.get('input[name="username"]')
    })

    it('Login', () => {
      cy.visit('/')
      cy.get('input[name="username"]').clear().type("readonly")
      cy.contains('Sign In').click()
    }) 
})