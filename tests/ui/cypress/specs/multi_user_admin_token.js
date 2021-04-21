let admin = { u: 'admin-token', p: 'secret' };

describe('admin API token', () => {
  it('The correct login form is shown', () => {
    cy.visit('/')

    // make sure we haven't been redirected away from Krill (as would be the
    // case if an OpenID Connect login form were shown)
    cy.url().should('include', Cypress.config('baseUrl'))

    // make sure that no user name field exists (as would be the case if the
    // built-in config file based local user login form were shown)
    cy.contains('Username').should('not.exist')

    // check that a password form input field and the text Password are shown on
    // the page
    cy.get(':password')
    cy.contains('Password')
  })

  it('Cannot login with empty password', () => {
    cy.visit('/')
    cy.get(':password').clear()
    cy.contains('Sign In').click()
    cy.contains('Please enter your password')
  })

  it('Cannot login with incorrect password', () => {
    cy.visit('/')
    cy.get(':password').clear().type('abc')
    cy.contains('Sign In').click()
    cy.contains('The credentials you specified are wrong')
  })

  it('Can login with correct password', () => {
    cy.visit('/')
    cy.get(':password').type(admin.p)
    cy.contains('Sign In').click()
    cy.contains('Sign In').should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(admin.u)
  })

  it('Can logout', () => {
    cy.visit('/')
    cy.get(':password').type(admin.p)
    cy.contains('Sign In').click()
    cy.contains('Sign In').should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(admin.u)
    cy.get('.logout').click()
    cy.contains('Sign In')
  })
})