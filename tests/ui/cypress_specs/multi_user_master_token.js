let master = { u: 'master-token@krill.conf', p: 'dummy-master-token' };

describe('Master API token', () => {
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
    cy.get(':password').type(master.p)
    cy.contains('Sign In').click()
    cy.contains('Sign In').should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(master.u)
  })

  it('Can logout', () => {
    cy.visit('/')
    cy.get(':password').type(master.p)
    cy.contains('Sign In').click()
    cy.contains('Sign In').should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(master.u)
    cy.get('.logout').click()
    cy.contains('Sign In')
  })

  it('Should be timed out', () => {
    cy.clock()

    // check that the metrics show zero logged in users
    cy.request('/metrics').its('body').should('include', 'krill_auth_session_cache_size 0')

    cy.visit('/')
    cy.get(':password').type(master.p)
    cy.contains('Sign In').click()

    // Check that we are logged in
    cy.contains('Sign In').should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(master.u)

    // check that the metrics still show zero logged in users, because the
    // master token auth provider has no concept of a login session, the token
    // is valid forever.
    cy.request('/metrics').its('body').should('include', 'krill_auth_session_cache_size 0')
  
    // Wait a minute and check that if we visit / we are not redirected to the
    // login page but instead are still logged in
    cy.tick(1*60*1000)
    cy.visit('/')
    cy.contains('Sign In').should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(master.u)

    // Skip ahead 30 minutes (so including the time already skipped we should
    // now have exceeded the Lagosta max idle time and be logged out)
    cy.tick(30*60*1000)
    cy.visit('/')
    cy.contains('Sign In')
    cy.get('#userinfo').should('not.exist')
  })

  it('Can create CA', () => {
    cy.visit('/')
    cy.get(':password').type(master.p)
    cy.contains('Sign In').click()
    cy.contains('Sign In').should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(master.u)
    cy.contains('Welcome to Krill')

    // create a CA
    cy.contains('CA Handle')
    cy.get('form input[type="text"]').type('dummy-ca-name')
    cy.contains('Create CA').click()
    cy.contains('OK').click()
    cy.contains('Certificate Authority')

    // we're no longer on the welcome page and the CA name we created is visible
    // on the page
    cy.contains('Welcome to Krill').should('not.exist')
    cy.contains('dummy-ca-name')
  })
})