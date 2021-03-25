// Team names and CAs they can access are defined in doc/policies/team-based-access-demo.polar.
// Team memberships and user roles within teams are defined in test-resources/ui/multi_user_team_based_access.conf.
// This test verifies that team roles and team CA rights work as expected, as defined in those files.

let t1ro = { u: 'team1ro@krill', p: 'team1ro' };
let t1rw = { u: 'team1rw@krill', p: 'team1rw' };
let t2ro = { u: 'team2ro@krill', p: 'team2ro' };
let t2rw = { u: 'team2rw@krill', p: 'team2rw' };

let create_ca_test_settings = [
  { d: 't1ro', u: t1ro.u, p: t1ro.p, o: false, ca: 'ca1', t: 'Red Team',  tr: 'Read Only' },
  { d: 't1rw', u: t1rw.u, p: t1rw.p, o: true,  ca: 'ca1', t: 'Red Team',  tr: 'Read Write' },
  { d: 't2ro', u: t2ro.u, p: t2ro.p, o: false, ca: 'ca2', t: 'Blue Team', tr: 'Read Only' },
  { d: 't2rw', u: t2rw.u, p: t2rw.p, o: true,  ca: 'ca2', t: 'Blue Team', tr: 'Read Write' },
];

describe('Config File users with custom team policy', () => {
  create_ca_test_settings.forEach(function (ts) {
    it('Create CA as ' + ts.d + ' user should ' + (ts.o ? 'succeed' : 'fail'), () => {
      cy.visit('/')
      cy.get('#login_id').type(ts.u)
      cy.get('#login_password').type(ts.p)
      cy.contains('Sign In').click()
      cy.contains(ts.u)
      cy.contains('Sign In').should('not.exist')
      cy.contains('Welcome to Krill')

      // verify our team and role
      cy.get('#userinfo')
      cy.get('#userinfo').click()
      cy.screenshot()
      cy.get('#userinfo_table').contains(ts.t)
      cy.get('#userinfo_table').contains(ts.tr)

      // create a CA
      cy.contains('CA Handle')
      cy.get('form input[type="text"]').type(ts.ca)
      cy.contains('Create CA').click()
      cy.contains('OK').click()

      // no longer on the welcome page
      if (ts.o) {
        cy.contains('Welcome to Krill').should('not.exist')
      } else {
        cy.contains('Welcome to Krill')
      }
    })
  })
})