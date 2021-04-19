// A note about strong password hashing login delays
// -----------------------------------------------------------------------------
// The strong password hashing on the client and server side when logging in with
// config file users causes the login process to take a few seconds. As such we
// extend the default timeout when checking for Sign In completion, like so:
//
//   cy.contains('Sign In', { timeout: 10000 }).should('not.exist')

let admin = { u: 'admin@krill', p: 'admin_pass' };
let readonly = { u: 'readonly@krill', p: 'readonly_pass' };
let readwrite = { u: 'readwrite@krill', p: 'readwrite_pass' };
let ca_name = 'dummy-ca-name';

let login_test_settings = [
  { d: 'empty', u: '', p: '', o: false },
  { d: 'admin token', u: 'secret', p: 'secret', o: false },
  { d: 'incorrect', u: 'wrong_user_name', p: 'wrong_password', o: false },
  { d: 'admin', u: admin.u, p: admin.p, o: true },
  { d: 'readonly', u: readonly.u, p: readonly.p, o: true },
  { d: 'readwrite', u: readwrite.u, p: readwrite.p, o: true },
];

describe('Config File users', () => {
  it('The correct login form is shown', () => {
    cy.visit('/')

    // make sure we haven't been redirected away from Krill (as would be the
    // case if an OpenID Connect login form were shown)
    cy.url().should('include', Cypress.config('baseUrl'))

    // make sure that user name field exists (which would not be the case if the
    // built-in admin token based login form were shown)
    cy.contains('Username')

    // check that a password form input field and the text Password are shown on
    // the page
    cy.get(':password')
    cy.contains('Password')
  })

  login_test_settings.forEach(function (ts) {
    it('Login with ' + ts.d + ' credentials should ' + (ts.o ? 'succeed' : 'fail'), () => {
      cy.visit('/')
      cy.contains('Username')
      cy.contains('Password')

      cy.get('input[placeholder="Your username"]').clear()
      cy.get(':password').clear()

      if (ts.u != '') cy.get('input[placeholder="Your username"]').type(ts.u)
      if (ts.p != '') cy.get(':password').type(ts.p)

      cy.contains('Sign In').click()

      if (ts.u == '') cy.contains('Please enter your username')
      if (ts.p == '') cy.contains('Please enter your password')

      if (ts.o) {
        cy.contains('Sign In', { timeout: 10000 }).should('not.exist')
        cy.get('#userinfo').click()
        cy.get('#userinfo_table').contains(ts.u)
      } else {
        cy.contains('Sign In')
      }
    })
  })

  it('Can logout', () => {
    cy.visit('/')
    cy.get('input[placeholder="Your username"]').type(admin.u)
    cy.get(':password').type(admin.p)
    cy.contains('Sign In').click()
    cy.contains('Sign In', { timeout: 10000 }).should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(admin.u)
    cy.get('.logout').click()
    cy.contains('Sign In')
  })

  it('Should be timed out', () => {
    // take manual control of time in the browser
    cy.clock()

    // login
    cy.visit('/')
    cy.get('input[placeholder="Your username"]').type(admin.u)
    cy.get(':password').type(admin.p)
    cy.contains('Sign In').click()
    cy.contains('Sign In', { timeout: 10000 }).should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(admin.u)

    // Skip ahead a minute and check that we are still logged in
    cy.tick(1 * 60 * 1000)
    cy.visit('/')
    cy.contains('Sign In').should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(admin.u)

    // Skip ahead till just before the idle timeout and check that we are still
    // logged in.
    cy.tick(28 * 60 * 1000)
    cy.visit('/')
    cy.contains('Sign In').should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(admin.u)

    // Skip ahead another 31 minutes to just beyond the UI 30 minute idle
    // timeout threshold and verify that we have been logged out
    cy.tick(31 * 60 * 1000)
    cy.visit('/')
    cy.get('#userinfo').should('not.exist')
    cy.contains('Sign In')
  })
})