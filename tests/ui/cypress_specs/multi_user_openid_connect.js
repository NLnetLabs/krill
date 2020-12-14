// The mock OpenID Connect provider only checks usernames, not passwords.
let admin        = { u: 'admin@krill' };
let readonly     = { u: 'readonly@krill' };
let readwrite    = { u: 'readwrite@krill' };
let shorttoken   = { u: 'shorttokenwithoutrefresh@krill' };
// let shortrefresh = { u: 'shorttokenwithrefresh@krill' };
let ca_name      = 'dummy-ca-name';

let login_test_settings = [
  { d: 'empty',        u: '',                o: false },
  { d: 'incorrect',    u: 'wrong_user_name', o: false },
  { d: 'admin',        u: admin.u,           o: true  },
  { d: 'readonly',     u: readonly.u,        o: true  },
  { d: 'readwrite',    u: readwrite.u,       o: true  },
];

describe('OpenID Connect users', () => {
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

  login_test_settings.forEach(function (ts) {
    it('Login with ' + ts.d + ' credentials should ' + (ts.o ? 'succeed' : 'fail'), () => {
      cy.visit('/')
      cy.url().should('not.include', Cypress.config('baseUrl'))
      cy.contains('Mock OpenID Connect login form')

      if (ts.u != '') cy.get('input[name="username"]').clear().type(ts.u)

      cy.contains('Sign In').click()

      // We should end up back in the Krill UI
      cy.url().should('include', Cypress.config('baseUrl'))

      if (ts.o) {
        cy.contains('Sign In').should('not.exist')
        cy.get('#userinfo').click()
        cy.get('#userinfo_table').contains(ts.u)
      } else if (ts.u == '') {
        cy.contains('No login credentials were supplied')
        cy.contains('return to the login page')
      } else {
        cy.contains('return to the login page')
      }
    })
  })

  it('Can logout', () => {
    // login
    cy.visit('/')
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]').clear().type(admin.u)
    cy.contains('Sign In').click()

    // verify that we are shown to be logged in to the Krill UI
    cy.contains('Sign In').should('not.exist')
    cy.url().should('include', Cypress.config('baseUrl'))
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(admin.u)

    // logout
    cy.get('.logout').click()

    // verify that we are shown the OpenID Connect provider login page
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]')
  })

  it.skip('Login receives short-lived token that cannot be refreshed', () => {
    cy.visit('/')
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]').clear().type(shorttoken.u)
    cy.contains('Sign In').click()

    cy.url().should('include', Cypress.config('baseUrl'))
    cy.contains('Sign In').should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(shorttoken.u)
    cy.contains(shorttoken.u)
    cy.contains('Welcome to Krill')

    // the token has a lifetime of 1 second and no refresh token, wait 2..
    cy.wait(2)

    // verify that we are shown the OpenID Connect provider login page
    cy.visit('/')
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]')
  })

  it.skip('Login receives short-lived refreshable token', () => {
    cy.visit('/')
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]').type(shortrefresh.u)
    cy.contains('Sign In').click()

    cy.url().should('include', Cypress.config('baseUrl'))
    cy.contains('Sign In').should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(shortrefresh.u)
    cy.contains(shorttoken.u)
    cy.contains('Welcome to Krill')

    // the token has a lifetime of 1 second and has a refresh token, wait 2..
    cy.wait(2)

    // verify that we are still logged in to Krill
    cy.visit('/')
    cy.url().should('include', Cypress.config('baseUrl'))
    cy.contains('Sign In').should('not.exist')
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(shortrefresh.u)
    cy.contains(shorttoken.u)
    cy.contains('Welcome to Krill')
  })
})