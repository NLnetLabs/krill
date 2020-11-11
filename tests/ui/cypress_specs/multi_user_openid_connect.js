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

    it('Cannot login with incorrect credentials', () => {
      cy.visit('/')
      cy.get('input[name="username"]').type("wrong_user_name")
      cy.contains('Sign In').click()
      // TODO: I should fail. How we can we tell?
    })

    it('Can login with admin credentials', () => {
      cy.visit('/')
      cy.get('input[name="username"]').type("admin@krill")
      cy.contains('Sign In').click()
      cy.contains('Logged in as: admin@krill')
    }) 

    it('Can logout', () => {
      // login
      cy.visit('/')
      cy.get('input[name="username"]').type("admin@krill")
      cy.contains('Sign In').click()

      // verify that we are shown to be logged in to the Krill UI
      cy.url().should('include', Cypress.config('baseUrl'))
      cy.contains('Logged in as: admin@krill')

      // logout
      cy.get('.logout').click()

      // verify that we are shown the OpenID Connect provider login page
      cy.contains('Logged in as:').should('not.exist')
      cy.url().should('not.include', Cypress.config('baseUrl'))
      cy.contains('Mock OpenID Connect login form')
      cy.get('input[name="username"]')
    })

    it('Can login with readonly credentials', () => {
      cy.visit('/')
      cy.get('input[name="username"]').type("readonly@krill")
      cy.contains('Sign In').click()
      cy.contains('Logged in as: readonly@krill')
    }) 

    it('Can login with readwrite credentials', () => {
      cy.visit('/')
      cy.get('input[name="username"]').type("readwrite@krill")
      cy.contains('Sign In').click()
      cy.contains('Logged in as: readwrite@krill')
    }) 
})