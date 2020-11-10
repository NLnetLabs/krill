describe('Config File Users', () => {
  it('The correct login form is shown', () => {
    cy.visit('/')

    // make sure we haven't been redirected away from Krill (as would be the
    // case if an OpenID Connect login form were shown)
    cy.url().should('include', Cypress.config('baseUrl'))

    // make sure that user name field exists (which would not be the case if the
    // built-in master token based login form were shown)
    cy.contains('Username')

    // check that a password form input field and the text Password are shown on
    // the page
    cy.get(':password')
    cy.contains('Password')
  })
  
  it('Cannot login with empty password', () => {
    cy.visit('/')
    cy.contains('Username')
    cy.contains('Password')
    cy.get(':password').clear()
    cy.contains('Sign In').click()
    cy.contains('Please enter your password')
  })

  it('Cannot login with master token', () => {
    cy.visit('/')
    cy.contains('Username')
    cy.contains('Password')
    cy.get(':password').type('dummy-master-token')
    cy.contains('Sign In').click()
    cy.contains('Please enter your username')
  })

  it('Cannot login with incorrect credentials', () => {
    cy.visit('/')
    cy.get('input[placeholder="Your username"]').type('wrong_user_name')
    cy.get(':password').clear().type('wrong_password')
    cy.contains('Sign In').click()
    cy.contains('The credentials you specified are wrong')
  })

  it('Can login with admin credentials', () => {
    cy.visit('/')
    cy.get('input[placeholder="Your username"]').type('admin@krill')
    cy.get(':password').type('admin_pass')
    cy.contains('Sign In').click()
    cy.contains('Logged in as: admin@krill')
  })

  it('Can logout', () => {
    cy.visit('/')
    cy.get('input[placeholder="Your username"]').type('admin@krill')
    cy.get(':password').type('admin_pass')
    cy.contains('Sign In').click()
    cy.contains('Logged in as: admin@krill')
    cy.get('.logout').click()
    cy.contains('Sign In')
  })

  it('Should be timed out', () => {
    // take manual control of time in the browser
    cy.clock()

    // login
    cy.visit('/')
    cy.get('input[placeholder="Your username"]').type('admin@krill')
    cy.get(':password').type('admin_pass')
    cy.contains('Sign In').click()
    cy.contains('Logged in as: admin@krill')

    // Skip ahead a minute and check that we are still logged in
    cy.tick(1*60*1000)
    cy.visit('/')
    cy.contains('Logged in as: admin@krill')
    cy.contains('Sign In').should('not.exist')

    // Skip ahead till just before the idle timeout and check that we are still
    // logged in.
    cy.tick(28*60*1000)
    cy.visit('/')
    cy.contains('Logged in as: admin@krill')
    cy.contains('Sign In').should('not.exist')

    // Skip ahead another 31 minutes to just beyond the UI 30 minute idle
    // timeout threshold and verify that we have been logged out
    cy.tick(31*60*1000)
    cy.visit('/')
    cy.contains('Logged in as').should('not.exist')
    cy.contains('Sign In')
  })

  it('Can login with readonly credentials', () => {
    cy.visit('/')
    cy.get('input[placeholder="Your username"]').type('readonly@krill')
    cy.get(':password').type('readonly_pass')
    cy.contains('Sign In').click()
    cy.contains('Logged in as: readonly@krill')
  })

  it('Cannot create CA as readnly user', () => {
    cy.visit('/')
    cy.get('input[placeholder="Your username"]').type('readonly@krill')
    cy.get(':password').type('readonly_pass')
    cy.contains('Sign In').click()
    cy.contains('Logged in as: readonly@krill')
    cy.contains('Welcome to Krill')

    // try to create a CA
    cy.contains('CA Handle')
    cy.get('form input[type="text"]').type('dummy-ca-name')
    cy.contains('Create CA').click()
    cy.contains('OK').click()

    // still on the welcome page but now an error is showing
    cy.contains('Welcome to Krill')
    cy.contains('Error')
  })

  it('Can login with readwrite credentials', () => {
    cy.visit('/')
    cy.get('input[placeholder="Your username"]').type('readwrite@krill')
    cy.get(':password').type('readwrite_pass')
    cy.contains('Sign In').click()
    cy.contains('Logged in as: readwrite@krill')
  })

  it('Can create CA as readwrite user', () => {
    cy.visit('/')
    cy.get('input[placeholder="Your username"]').type('readwrite@krill')
    cy.get(':password').type('readwrite_pass')
    cy.contains('Sign In').click()
    cy.contains('Logged in as: readwrite@krill')
    cy.contains('Welcome to Krill')

    // try to create a CA
    cy.contains('CA Handle')
    cy.get('form input[type="text"]').type('dummy-ca-name')
    cy.contains('Create CA').click()
    cy.contains('OK').click()

    // we're no longer on the welcome page and the CA name we created is visible
    // on the page
    cy.contains('Welcome to Krill').should('not.exist')
    cy.contains('dummy-ca-name')
  })
})