let login_test_settings = [
  { u: 'shorttokenwithrefresh@krill', o: true },
  { u: 'shorttokenwithoutrefresh@krill', o: false }
];

describe('OpenID Connect provider with OAuth 2 revocation', () => {
  login_test_settings.forEach(function (ts) {
    it('Logout when logged in as user ' + ts.u + ' should ' + (ts.o ? 'successfully' : 'fail to') + ' revoke the token', () => {
      cy.intercept({ url: /^https:\/\/localhost:1818\/authorize/ }).as('getLoginForm')
      cy.intercept({ url: /^https:\/\/localhost:1818\/login_form_submit/ }).as('submitLoginForm')
      cy.intercept({ url: /^https:\/\/localhost:3000\/auth\/callback/ }).as('completeTheLoginInKrill')
      cy.intercept({ url: /^https:\/\/localhost:3000\/index\.html/ }).as('afterLoginCompleteInKrill')

      cy.visit('/')
      cy.url().should('not.include', Cypress.config('baseUrl'))
      cy.contains('Mock OpenID Connect login form')
      cy.get('input[name="username"]').clear().type(ts.u)
      cy.contains('Sign In').click()

      cy.wait(['@getLoginForm', '@submitLoginForm', '@completeTheLoginInKrill', '@afterLoginCompleteInKrill'])

      // We should end up back in the Krill UI
      cy.url().should('include', Cypress.config('baseUrl'))
      cy.contains('Sign In').should('not.exist')
      cy.get('#userinfo').click()
      cy.get('#userinfo_table').contains(ts.u)
      cy.get('#userinfo_table').contains("role")

      // verify that the mock provider thinks the user is logged in
      cy.request({ url: 'https://127.0.0.1:1818/test/is_user_logged_in?username=' + ts.u, failOnStatusCode: false }).its('status').should('eq', 200)

      // logout, and thus trigger the invocation of the OAuth 2.0 token revocation endpoint
      // for users with both a refresh token and an access token first Krill will try to revoke the refresh token
      // then will retry if that fails with the access token
      cy.intercept({ url: /^https:\/\/localhost:3000\/auth\/logout/ }).as('getLogoutURL')
      cy.get('.logout').click()

      // verify that we are shown the OpenID Connect provider login page
      cy.wait('@getLogoutURL').its('response.statusCode').should('eq', 200)
      cy.url().should('not.include', Cypress.config('baseUrl'))
      cy.contains('Mock OpenID Connect login form')
      cy.get('input[name="username"]')

      if (ts.o) {
        // verify that the mock provider thinks the user is now logged out
        cy.request({ url: 'https://127.0.0.1:1818/test/is_user_logged_in?username=' + ts.u, failOnStatusCode: false }).its('status').should('eq', 400)
      } else {
        // verify that the mock provider thinks the user is still logged in (because it only supports revocation by
        // refresh token, not by access token)
        cy.request({ url: 'https://127.0.0.1:1818/test/is_user_logged_in?username=' + ts.u, failOnStatusCode: false }).its('status').should('eq', 200)
      }
    })
  })
})