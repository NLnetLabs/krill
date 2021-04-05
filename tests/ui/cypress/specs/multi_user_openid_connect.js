// Matches daemon::auth::providers::openid_connect::http_client::openid_connect_provider_timeout() when test mode is
// enabled.
const KRILL_TEST_HTTP_CLIENT_TIMEOUT_SECS = 5;

// The mock OpenID Connect provider only checks usernames, not passwords.
const admin = { u: 'adm@krill' }
const readonly = { u: 'ro@krill' }
const readwrite = { u: 'rw@krill' }
const shorttoken = { u: 'shorttokenwithoutrefresh@krill' }
const shortrefresh = { u: 'shorttokenwithrefresh@krill' }
const badidtoken = { u: 'non-spec-compliant-idtoken-payload' }
const badrole = { u: 'user-with-unknown-role' }
const refreshinvalidrequest = { u: 'user-with-invalid-request-on-refresh' }
const refreshinvalidclient = { u: 'user-with-invalid-client-on-refresh' }
const wrongcsrfstate = { u: 'user-with-wrong-csrf-state-value' }
const ca_name = 'dummy-ca-name'

// d: description, u: user, o: outcome, fm: failure mode, r: role
const login_test_settings = [
  { d: 'empty', u: '', o: false },
  { d: 'incorrect', u: 'wrong_user_name', o: false, fm: 'unknown_user' },
  { d: 'admin', u: admin.u, o: true, r: 'admin' },
  { d: 'readonly', u: readonly.u, o: true, r: 'readonly' },
  { d: 'readwrite', u: readwrite.u, o: true, r: 'readwrite' },
  { d: 'badidtoken', u: badidtoken.u, o: false, fm: 'malformed_id_token' },
  { d: 'badrole', u: badrole.u, o: false },
  { d: 'wrongcsrfstate', u: wrongcsrfstate.u, o: false, fm: 'wrong_csrf_state' },
]

// o: outcome
const short_token_test_settings = [
  { ca: 'some-handle-name', o: true, token_secs: 5, create_ca_after_secs: 0 },          // should succeed with a freshly issued token
  { ca: 'some-other-handle-name', o: true, token_secs: 10, create_ca_after_secs: 5 },   // should succeed with a token due to expire but not yet expired
  { ca: 'yet-another-handle-name', o: false, token_secs: 5, create_ca_after_secs: 10 }, // should fail after token expiration
]

// fm: failure mode
const create_ca_settings_401 = [
  'invalid_request',
  'invalid_grant',
  'invalid_client',
  'http_500',
  'http_503',
].map((fm) => ({
  fm: fm,
  responseCode: 401,
}))

// fm: failure mode
const create_ca_settings_403 = [
  'unauthorized_client',
  'invalid_scope',
  'unsupported_grant_type',
].map((fm) => ({
  fm: fm,
  responseCode: 403,
}))

describe('OpenID Connect provider with RP-Initiated logout', () => {
  it('The correct login form is shown', () => {
    cy.intercept('GET', '/api/v1/authorized').as('isAuthorized')
    cy.intercept('GET', '/auth/login').as('getLoginURL')
    cy.intercept('GET', /^https:\/\/localhost:1818\/authorize.+/).as('oidcLoginForm')
    cy.visit('/')
    cy.wait(['@isAuthorized', '@getLoginURL', '@oidcLoginForm'])

    // make sure we haven't been redirected away from Krill (as would be the
    // case if an OpenID Connect login form were shown)
    cy.url().should('not.include', Cypress.config('baseUrl'))

    // make sure that this is our mock OpenID Connect provider
    cy.contains('Mock OpenID Connect login form')

    // check that a username input field is shown on the page
    cy.get('input[name="username"]')
  })

  login_test_settings.forEach(function (ts) {
    it(
      'Login with ' +
        ts.d +
        ' credentials should ' +
        (ts.o ? 'succeed with the expected user info' : 'fail with the expected error'),
      () => {
        cy.visit('/')
        cy.url().should('not.include', Cypress.config('baseUrl'))
        cy.contains('Mock OpenID Connect login form')

        // Login, and while doing so specify the behaviour we want the OpenID Connect mock to exhibit for this user
        if (ts.u != '') {
          cy.get('input[name="username"]').clear().type(ts.u)
        }
        if (ts.fm) {
          // Cause the mock to exhibit the requested failure mode 
          cy.get('select[name="failure_mode"]').select(ts.fm)
        }
        if (ts.r) {
          // Force the mock to respond with a role attribute for this user
          cy.get('input[name="userattr1"]').clear().type('role')
          cy.get('input[name="userattrval1"]').clear().type(ts.r)
        }

        cy.contains('Sign In').click()

        // We should end up back in the Krill UI
        cy.url().should('include', Cypress.config('baseUrl'))

        if (ts.o) {
          // A good outcome, i.e. login should have succeeded
          cy.contains('Sign In').should('not.exist')
          cy.get('#userinfo').click()
          cy.get('#userinfo_table').contains(ts.u)
          cy.get('#userinfo_table').contains(ts.r) // assumes that ts.r is not a substring of ts.u
        } else if (ts.d == 'badidtoken') {
          cy.contains('OpenID Connect: Code exchange failed: Failed to parse server response')
          cy.contains('return to the login page')
        } else if (ts.d == 'badrole') {
          cy.contains(
            'Your user does not have sufficient rights to perform this action. Please contact your administrator.'
          )
          cy.contains('return to the login page')
        } else if (ts.d == 'wrongcsrfstate') {
          cy.contains('CSRF token mismatch')
        } else {
          cy.contains('The supplied login credentials were incorrect')
          cy.contains('return to the login page')
        }
      }
    )
  })

  it('Can logout', () => {
    // login
    cy.visit('/')
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]').clear().type(admin.u)
    cy.get('input[name="userattr1"]').clear().type('role') // a role is required to be able to login
    cy.get('input[name="userattrval1"]').clear().type('admin')
    cy.contains('Sign In').click()

    // verify that we are shown to be logged in to the Krill UI
    cy.contains('Sign In').should('not.exist')
    cy.url().should('include', Cypress.config('baseUrl'))
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(admin.u)

    // verify that the mock provider thinks the user is logged in
    cy.request({ url: 'https://127.0.0.1:1818/test/is_user_logged_in?username=' + admin.u, failOnStatusCode: false }).its('status').should('eq', 200)

    // logout
    cy.intercept('GET', /^https:\/\/localhost:1818\/logout.+/).as('oidcLogout')
    cy.get('.logout').click()
    cy.wait('@oidcLogout').its('response.statusCode').should('eq', 302)

    // verify that the mock provider thinks the user is now logged out
    cy.request({ url: 'https://127.0.0.1:1818/test/is_user_logged_in?username=' + admin.u, failOnStatusCode: false }).its('status').should('eq', 400)

    // verify that we are shown the OpenID Connect provider login page
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]')
  })

  it('Login with short-lived non-refreshable token and try to refresh page', () => {
    // login
    cy.visit('/')
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]').clear().type(shorttoken.u)
    cy.get('input[name="userattr1"]').clear().type('role')         // a role is required to be able to login
    cy.get('input[name="userattrval1"]').clear().type('readwrite')
    cy.get('input[name="refresh"]').uncheck()                      // prevent issuing of refresh tokens for this user
    cy.contains('Sign In').click()

    // verify that we are shown to be logged in to the Krill UI
    cy.contains('Sign In').should('not.exist')
    cy.url().should('include', Cypress.config('baseUrl'))
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(shorttoken.u)

    // the token has a lifetime of 5 second and no refresh token
    // wait 6 seconds...
    // note: a shorter token with a 1 second lifetime doesn't work in the GitHub
    // Action runner environment because the token has sometimes already expired
    // by the time Krill verifies it!
    cy.wait(6000)

    // verify that if we reload the Krill UI we are shown the OpenID Connect
    // provider login page
    cy.intercept('GET', '/auth/login').as('getLoginURL')
    cy.intercept('GET', /^https:\/\/localhost:1818\/authorize.+/).as('oidcLoginForm')
    cy.visit('/')
    cy.wait(['@getLoginURL', '@oidcLoginForm'])
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
  })

  short_token_test_settings.forEach((ts) =>
    it('Login with short-lived non-refreshable token and try to create a CA after ' + ts.create_ca_after_secs + ' out of ' + ts.token_secs + ' secs' + ' should ' + (ts.o ? 'succeed' : 'fail'), () => {
      // note: a short token with a 1 second lifetime doesn't work in the GitHub
      // Action runner environment because the token has sometimes already expired
      // by the time Krill verifies it! And we also want to test that we still have
      // rights when less than half the token lifetime is remaining (as at this
      // point Krill switches from considering the token to be ACTIVE to NEEDS
      // REFRESH), and for a short lifetime like 5 seconds window in which to time
      // the test to check after 3 seconds but before 5 seconds is just too small,
      // so we use a longer lifetime for this test.

      // login
      cy.visit('/')
      cy.url().should('not.include', Cypress.config('baseUrl'))
      cy.contains('Mock OpenID Connect login form')
      cy.get('input[name="username"]').clear().type(shorttoken.u + '_delay_' + ts.create_ca_after_secs)
      cy.get('input[name="userattr1"]').clear().type('role')         // a role is required to be able to login
      cy.get('input[name="userattrval1"]').clear().type('readwrite')
      cy.get('input[name="userattr2"]').clear().type('inc_cas')      // force the create CA welcome page to show
      cy.get('input[name="userattrval2"]').clear().type(ts.ca)       //   (by making Lagosta think there are no CAs)
      cy.get('input[name="refresh"]').uncheck()                      // prevent issuing of refresh tokens for this user
      cy.get('input[name="token_secs"]').clear().type(ts.token_secs) // control the lifetime of the issued access token
      cy.contains('Sign In').click()

      // record the approximate time at which the token was issued
      let issued_at_ms = Date.now()
      
      // verify that we are shown to be logged in to the Krill UI
      cy.contains('Sign In').should('not.exist')
      cy.url().should('include', Cypress.config('baseUrl'))
      cy.get('#userinfo').click()
      cy.get('#userinfo_table').contains(shorttoken.u)

      // verify that we are shown the CA create page
      cy.contains('Welcome to Krill')

      // calculate the remaining time necessary to wait until the
      // create_ca_after_secs moment
      let time_elapsed_ms = Date.now() - issued_at_ms
      let time_remaining_ms = ts.create_ca_after_secs*1000 - time_elapsed_ms
      cy.wait(time_remaining_ms)

      // Try to create a CA, by typing in the input, clicking the 'Create CA' button
      // and then clicking 'Ok'. This should fail, since the token can't be refreshed.
      cy.intercept('POST', '/api/v1/cas').as('createCA')
      cy.contains('CA Handle')
      cy.get('form input[type="text"]').type(ts.ca)
      cy.contains('Create CA').click()
      cy.contains('OK').click()

      if (ts.o) {
        cy.wait('@createCA').its('response.statusCode').should('eq', 200)
      } else {
        cy.wait('@createCA').its('response.statusCode').should('eq', 401)
        cy.contains('Your login session has expired. Please login again.')
      }
    })
  );

  [...create_ca_settings_401, ...create_ca_settings_403].forEach((ts) =>
    it('Try to create a CA with mock failure mode ' + ts.fm + ' enabled', () => {
      let user_name = 'user_' + ts.fm;
      let ca_name = 'some-unique-handle-name-' + Date.now();

      // login
      cy.visit('/')
      cy.url().should('not.include', Cypress.config('baseUrl'))
      cy.contains('Mock OpenID Connect login form')
      cy.get('input[name="username"]').clear().type(user_name)
      cy.get('input[name="userattr1"]').clear().type('role')         // a role is required to be able to login
      cy.get('input[name="userattrval1"]').clear().type('readwrite')
      cy.get('input[name="userattr2"]').clear().type('inc_cas')      // force the create CA welcome page to show
      cy.get('input[name="userattrval2"]').clear().type(ca_name)     //   (by making Lagosta think there are no CAs)
      cy.get('select[name="failure_mode"]').select(ts.fm)
      cy.get('select[name="failure_endpoint"]').select('token')
      cy.contains('Sign In').click()

      // verify that we are shown to be logged in to the Krill UI
      cy.contains('Sign In').should('not.exist')
      cy.url().should('include', Cypress.config('baseUrl'))
      cy.get('#userinfo').click()
      cy.get('#userinfo_table').contains(user_name)

      // verify that we are shown the create CA welcome page
      cy.contains('Welcome to Krill')

      // the token has a lifetime of 5 second and no refresh token
      // wait 6 seconds...
      // note: a shorter token with a 1 second lifetime doesn't work in the GitHub
      // Action runner environment because the token has sometimes already expired
      // by the time Krill verifies it!
      cy.wait(6000)

      // Try to create a CA, by typing in the input, clicking the 'Create CA' button
      // and then clicking 'Ok'. This should fail, since the mock server should return a
      // exhibit the undesirable behaviour we configured which should result in an
      // error from Krill.
      cy.intercept('POST', '/api/v1/cas').as('createCA')
      cy.contains('CA Handle')
      cy.get('form input[type="text"]').type(ca_name)
      cy.contains('Create CA').click()
      cy.contains('OK').click()  

      cy.wait('@createCA').its('response.statusCode').should('eq', ts.responseCode)
    })
  )

  it('Login with short-lived refreshable token and try to refresh page', () => {
    let token_secs = 2;

    // login
    cy.visit('/')
    cy.url().should('not.include', Cypress.config('baseUrl'))
    cy.contains('Mock OpenID Connect login form')
    cy.get('input[name="username"]').clear().type(shortrefresh.u)
    cy.get('input[name="userattr1"]').clear().type('role')         // a role is required to be able to login
    cy.get('input[name="userattrval1"]').clear().type('readonly')
    cy.get('input[name="token_secs"]').clear().type(token_secs)    // control the lifetime of the issued access token
    cy.contains('Sign In').click()

    // verify that we are shown to be logged in to the Krill UI
    cy.contains('Sign In').should('not.exist')
    cy.url().should('include', Cypress.config('baseUrl'))
    cy.get('#userinfo').click()
    cy.get('#userinfo_table').contains(shortrefresh.u)

    for (let i = 0; i < 5; i++) {
      // the token has a lifetime of 2 seconds and has a refresh token
      // wait 3 seconds..
      // note: a shorter token with a 1 second lifetime doesn't work in the
      // GitHub Action runner environment because the token has sometimes
      // already expired by the time Krill verifies it!
      cy.wait(1000 * (token_secs + 1))

      // verify that we are still logged in to Krill
      cy.visit('/')
      cy.url().should('include', Cypress.config('baseUrl'))
      cy.contains('Sign In').should('not.exist')
      cy.get('#userinfo').click()
      cy.get('#userinfo_table').contains(shortrefresh.u)
    }
  });

  [-2, +2].forEach((timeout_adjust_secs) =>
    it('Slow provider response (' + (timeout_adjust_secs < 0 ? 'within' : 'beyond') + ' Krill HTTP client timeout) is handled correctly', () => {
      let name_prefix = 'slow-response-';
      let name_postfix = (timeout_adjust_secs < 0 ? 'within' : 'beyond') + '-krill-max';
      let user_name = name_prefix + name_postfix;
      let ca_name = name_prefix + 'ca-' + name_postfix;
      let token_secs = 2; // we can't set it too low otherwise the initial token can expire before Krill sees it!
      let delay_secs = KRILL_TEST_HTTP_CLIENT_TIMEOUT_SECS + timeout_adjust_secs;

      // login
      cy.visit('/')
      cy.url().should('not.include', Cypress.config('baseUrl'))
      cy.contains('Mock OpenID Connect login form')
      cy.get('input[name="username"]').clear().type(user_name)
      cy.get('input[name="userattr1"]').clear().type('role')         // a role is required to be able to login
      cy.get('input[name="userattrval1"]').clear().type('readwrite')
      cy.get('input[name="userattr2"]').clear().type('inc_cas')      // force the create CA welcome page to show
      cy.get('input[name="userattrval2"]').clear().type(ca_name)     //   (by making Lagosta think there are no CAs)
      cy.get('select[name="failure_mode"]').select('slow_response')
      cy.get('select[name="failure_endpoint"]').select('token')
      cy.get('input[name="failure_param"]').clear().type(delay_secs) // control the delay at the provider
      cy.get('input[name="token_secs"]').clear().type(token_secs)    // control the lifetime of the issued access token
      cy.contains('Sign In').click()

      // record the approximate time at which the token was issued
      let issued_at_ms = Date.now()

      // verify that we are shown to be logged in to the Krill UI
      cy.contains('Sign In').should('not.exist')
      cy.url().should('include', Cypress.config('baseUrl'))
      cy.get('#userinfo').click()
      cy.get('#userinfo_table').contains(user_name)

      // verify that we are shown the create CA welcome page
      cy.contains('Welcome to Krill')

      // wait for the access token issued to Krill to expire so that it is forced to use the provider token endpoint to
      // exchange the refresh token for a new access token
      let time_elapsed_ms = Date.now() - issued_at_ms
      let time_till_after_expiration_ms = (token_secs * 1000) - time_elapsed_ms + 1000
      cy.log('Waiting ' + time_till_after_expiration_ms + 'ms until the Krill access token ' + token_secs*1000 + 'ms expiration point should have passed')
      cy.wait(time_till_after_expiration_ms)

      // Try to create a CA, by typing in the input, clicking the 'Create CA' button and then clicking 'Ok'.
      cy.intercept('POST', '/api/v1/cas').as('createCA')
      cy.contains('CA Handle')
      cy.get('form input[type="text"]').type(ca_name)
      cy.contains('Create CA').click()
      cy.contains('OK').click()  

      // Verify that the attempt to create the CA occurred.
      //
      // In the case where we configure the provider to respond slowly, but still within the Krill HTTP client timeout,
      // the CA creation attempt should be successful, and the response should have a new bearer token piggybacked on it
      // (which resulted from the token refresh attempt).
      //
      // In the case where we configure the provider to take longer to respond than Krill will wait, the CA creation
      // attempt should fail because Krill should have been unable to refresh its expired access token and thus should
      // deny the CA creation request.
      let expected_status_code = (timeout_adjust_secs < 0 ? 200 : 401);
      let time_till_after_provider_delay_is_over_ms = delay_secs * 1000;
      let time_to_wait_ms = time_till_after_provider_delay_is_over_ms + 3000;
      if (timeout_adjust_secs < 0) {
        cy.log('Expecting within ' + time_till_after_provider_delay_is_over_ms + 'ms the provider to finish delaying and for Krill to create the CA')
      } else {
        cy.log('Expecting Krill to timeout the provider before the ' + time_till_after_provider_delay_is_over_ms + 'ms remaining provider delay elapses')
      }
      cy.log('Waiting max ' + time_to_wait_ms + 'ms for Krill to respond to the CA create request')
      cy.wait('@createCA', { responseTimeout: time_to_wait_ms }).its('response.statusCode').should('eq', expected_status_code)
    })
  )
})
