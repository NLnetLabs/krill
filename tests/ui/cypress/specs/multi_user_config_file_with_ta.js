// Difficulty entering XML into Lagosta XML input fields:
// ------------------------------------------------------
// Using cy.type() to enter XML into these fields is extremely slow, one
// animated character at a time. I haven't yet found a way to copy-paste into
// them. Setting the text directly can be done but there is a challenge that has
// to be worked around which is that the fields use Prism Editor JS to syntax
// highlight the XML. Prism Editor manages the content as a rich HTML child node
// structure. Just replacing the content with a new text node doesn't work as
// the Lagosta JS code reading the field content doesn't get the content as
// set for some reason. The set text also doesn't get syntax highlighted. What
// seems to work however is causing a keyboard event in the field after the text
// has been set, e.g. pressing the End key.
//
// To summarize, the following works quickly:
//   cy.get('... pre[contenteditable="true"]').invoke('text', xml)
//   cy.get('... pre[contenteditable="true"]').type('{end}')
// 
// This is less hacky but very slow: (even with "type(xml, {delay: 0}))")
//   cy.get('... pre[contenteditable="true"]').clear().type(xml)

let admin     = { u: 'admin@krill',     p: 'admin'     };
let readonly  = { u: 'readonly@krill',  p: 'readonly'  };
let readwrite = { u: 'readwrite@krill', p: 'readwrite' };
let rohelper  = { u: 'rohelper@krill',  p: 'rohelper'  };

// For the tests below to work these users must only have access to a single CA,
// at the time of CA creation, otherwise only the first user gets to create a CA,
// after that Lagosta doesn't prompt to create a CA as the user can already see
// that one exists.
//
// For the read only user to be able to see the repository and parent management
// UI they must be able to get past the "Welcome to Krill" screen which prompts
// to create a CA, something the read only user cannot do. Therefore the CA for
// the read only user needs to be created for it by another user, and should be
// tested for CA creation failure *before* that CA is created.
let create_ca_test_settings = [
  { d: 'readonly',  u: readonly.u,  p: readonly.p,  o: false, ca: 'ca_readonly' },
  { d: 'readwrite', u: readwrite.u, p: readwrite.p, o: true,  ca: 'ca_readwrite' },
  { d: 'admin',     u: admin.u,     p: admin.p,     o: true,  ca: 'ca_admin' },
  { d: 'rohelper',  u: rohelper.u,  p: rohelper.p,  o: true,  ca: 'ca_readonly' },  // create the CA for the readonly user as they cannot do it themselves
];                                                                                  

let register_publisher_test_settings = [
  { d: 'readonly',  u: readonly.u,  p: readonly.p,  o: false, a: 'Register',   ca: 'ca_readonly' },
  { d: 'readwrite', u: readwrite.u, p: readwrite.p, o: true,  a: 'Register',   ca: 'ca_readwrite' },
  { d: 'admin',     u: admin.u,     p: admin.p,     o: true,  a: 'Register',   ca: 'ca_admin' },
  { d: 'rohelper',  u: rohelper.u,  p: rohelper.p,  o: true,  a: 'Unregister', ca: 'ca_readonly' }, // unregister the half-registered publisher created by the readonly user
  { d: 'rohelper',  u: rohelper.u,  p: rohelper.p,  o: true,  a: 'Register',   ca: 'ca_readonly' }, // re-register it properly now
];

let register_parent_test_settings = [
  { d: 'readonly',  u: readonly.u,  p: readonly.p,  o: false, a: 'Register',   ca: 'ca_readonly' },
  { d: 'readwrite', u: readwrite.u, p: readwrite.p, o: true,  a: 'Register',   ca: 'ca_readwrite' },
  { d: 'admin',     u: admin.u,     p: admin.p,     o: true,  a: 'Register',   ca: 'ca_admin' },
  { d: 'rohelper',  u: rohelper.u,  p: rohelper.p,  o: true,  a: 'Unregister', ca: 'ca_readonly' }, // unregister the half-registered parent created by the readonly user
  { d: 'rohelper',  u: rohelper.u,  p: rohelper.p,  o: true,  a: 'Register',   ca: 'ca_readonly' }, // re-register it properly now
];

let add_roa_test_settings = [
  { d: 'readonly',  u: readonly.u,  p: readonly.p,  o: false, ca: 'ca_readonly' },
  { d: 'readwrite', u: readwrite.u, p: readwrite.p, o: true,  ca: 'ca_readwrite' },
  { d: 'admin',     u: admin.u,     p: admin.p,     o: true,  ca: 'ca_admin' },
];

describe('Config File Users with TA', () => {
  create_ca_test_settings.forEach(function (ts) {
    it('Create CA as ' + ts.d + ' user should ' + (ts.o ? 'succeed' : 'fail'), () => {
      cy.visit('/')
      cy.get('#login_id').type(ts.u)
      cy.get('#login_password').type(ts.p)
      cy.contains('Sign In').click()
      cy.contains(ts.u)
      cy.contains('Sign In').should('not.exist')
      cy.contains('Welcome to Krill')

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

  register_publisher_test_settings.forEach(function (ts) {
    it(ts.a + ' CA ' + ts.ca + ' with repository as ' + ts.d + ' user should ' + (ts.o ? 'succeed' : 'fail'), () => {
      if (ts.a == 'Register') {
        cy.intercept('GET', '/api/v1/cas/' + ts.ca + '/repo/request.xml').as('getRepoRequestXML')

        cy.visit('/')
        cy.get('#login_id').type(ts.u)
        cy.get('#login_password').type(ts.p)
        cy.contains('Sign In').click()
        cy.contains(ts.u)
        cy.contains('Sign In').should('not.exist')

        // wait for Lagosta to finish fetching the repository request XML
        cy.wait('@getRepoRequestXML').its('response.statusCode').should('eq', 200)

        // grab the repository tab publisher request XML from the Krill UI
        cy.get('div#tab-repo').click()
        cy.get('div#pane-repo pre[contenteditable="false"] code').contains('<publisher_request')
        cy.get('div#pane-repo pre[contenteditable="false"] code').invoke('text').then(pub_req_xml => {
          // use the local testbed UI to submit the request to register the publisher
          cy.visit("/index.html#/testbed")

          // enter the request XML into the testbed UI edit field
          cy.get('div#tab-addPublisher').contains('Register Publisher').click()
          cy.get('#addPublisher pre[contenteditable="true"]').invoke('text', pub_req_xml)
          cy.get('#addPublisher pre[contenteditable="true"]').type('{end}')
          cy.get('#addPublisher button').contains('Register publisher').click()
          cy.get('div[role="dialog"] button').contains('OK').click()
          cy.contains('has been added to the testbed')

          // note: publisher registration succeeds even for the readonly user
          // because for the testbed half of the XML exchange the readonly user is
          // automatically promoted for the duration of the request to the
          // internal 'testbed' user, so that the testbed is usable without
          // requiring user accounts.

          // grab the repository response XML from the testbed UI
          cy.get('#addPublisher pre[contenteditable="false"]').contains('<repository_response')
          cy.get('#addPublisher pre[contenteditable="false"]').invoke('text').then(repo_resp_xml => {
            // navigate back to Krill
            cy.visit("/")

            // enter the response XML into the Krill UI edit field
            cy.get('div#tab-repo').click()
            cy.get('div#pane-repo pre[contenteditable="true"]').invoke('text', repo_resp_xml)
            cy.get('div#pane-repo pre[contenteditable="true"]').type('{end}')
            cy.get('div#pane-repo button').contains('Confirm').click()

            if (ts.o) {
              cy.contains('Success')
              cy.contains('Error').should('not.exist')
            } else {
              cy.contains('Success').should('not.exist')
              cy.contains('Error')
            }
          })
        })
      } else {
        // use the local testbed UI to unregister the publisher
        cy.visit("/index.html#/testbed")

        // enter the registered publisher name into the testbed UI edit field
        cy.get('div#tab-removePublisher').contains('Unregister Publisher').click()
        cy.get('#removePublisher input[placeholder="Enter the Publisher name to remove"]').type(ts.ca)
        cy.get('#removePublisher button').contains('Remove publisher').click()
        cy.get('div[role="dialog"] button').contains('OK').click()

        if (ts.o) {
          cy.contains('has been removed')
        } else {
          cy.contains('has been removed').should('not.exist')
        }
      }
    })
  })

  register_parent_test_settings.forEach(function (ts) {
    it(ts.a + ' CA ' + ts.ca + ' with parent as ' + ts.d + ' user should ' + (ts.o ? 'succeed' : 'fail'), () => {
      if (ts.a == 'Register') {
        cy.intercept('GET', '/api/v1/cas/' + ts.ca + '/child_request.xml').as('getChildRequestXML')

        cy.visit('/')
        cy.get('input[placeholder="Your username"]').type(ts.u)
        cy.get(':password').type(ts.p)
        cy.contains('Sign In').click()
        cy.contains(ts.u)
        cy.contains('Sign In').should('not.exist')

        // wait for Lagosta to finish fetching the repository request XML
        cy.wait('@getChildRequestXML').its('response.statusCode').should('eq', 200)

        // grab the parents tab child request XML from the Krill UI
        cy.get('div#tab-parents').click()
        cy.get('div#pane-parents pre[contenteditable="false"] code').contains("<child_request")
        cy.get('div#pane-parents pre[contenteditable="false"] code').invoke('text').then(child_req_xml => {
          // use the local testbed UI to submit the request to register the child
          cy.visit("/index.html#/testbed")

          // enter the request XML into the testbed UI edit field
          cy.get('div#tab-addChild').contains('Register CA').click()
          cy.get('#addChild pre[contenteditable="true"]').invoke('text', child_req_xml)
          cy.get('#addChild pre[contenteditable="true"]').type('{end}')
          cy.get('#addChild input[placeholder^="The AS resources"]').type('AS18')
          cy.get('#addChild input[placeholder^="The IPv4 resources"]').type('10.0.0.0/24')
          cy.get('#addChild button').contains('Register child CA').click()
          cy.get('div[role="dialog"] button').contains('OK').click()
          cy.contains('has been added to the testbed')

          // grab the parent response XML from the testbed UI
          cy.get('#addChild pre[contenteditable="false"]').contains("<parent_response")
          cy.get('#addChild pre[contenteditable="false"]').invoke('text').then(parent_resp_xml => {
            // navigate back to Krill
            cy.visit("/")

            // enter the response XML into the Krill UI edit field
            cy.get('div#tab-parents').click()
            cy.get('div#pane-parents pre[contenteditable="true"]').invoke('text', parent_resp_xml)
            cy.get('div#pane-parents pre[contenteditable="true"]').type('{end}')
            cy.get('div#pane-parents button').contains('Confirm').click()

            if (ts.o) {
              cy.contains('Success')
              cy.contains('Error').should('not.exist')
              // wait for the parent registration to complete inside Krill and
              // for the details to appear in the Lagosta UI
              cy.get('div#tab-parents').click().get('body').contains('Add an additional parent')
            } else {
              cy.contains('Success').should('not.exist')
              cy.contains('Error')
            }
          })
        })
      } else {
        // use the local testbed UI to unregister the parent
        cy.visit("/index.html#/testbed")

        // enter the registered parent name into the testbed UI edit field
        cy.get('div#tab-removeChild').contains('Unregister CA').click()
        cy.get('#removeChild input[placeholder="Enter the CA name to remove"]').type(ts.ca)
        cy.get('#removeChild button').contains('Remove child CA').click()
        cy.get('div[role="dialog"] button').contains('OK').click()

        if (ts.o) {
          cy.contains('has been removed')
        } else {
          cy.contains('has been removed').should('not.exist')
        }
      }
    })
  })

  add_roa_test_settings.forEach(function (ts) {
    it('Add ROA for CA ' + ts.ca + ' as ' + ts.d + ' user should ' + (ts.o ? 'succeed' : 'fail'), () => {
      cy.intercept('GET', '/api/v1/cas/' + ts.ca + '/routes/analysis/full').as('analyzeRoutes')

      cy.visit('/')
      cy.get('input[placeholder="Your username"]').type(ts.u)
      cy.get(':password').type(ts.p)
      cy.contains('Sign In').click()
      cy.contains(ts.u)
      cy.contains('Sign In').should('not.exist')

      // Add a ROA
      cy.get('div#tab-roas').click()
      cy.get('body').then(($body) => {
        // Check if Krill has issued the resources to the CA yet by seeing if the UI was able to fetch them, if it
        // wasn't then it shows a "Click here to refresh" link. If the link exists, don't click it immediately as that
        // will just result in the same lack of resources, instead give Krill some time (5 seconds) in this case then
        // click the refresh link and then make sure that the link no longer exists (because resources were found).
        // Ideally we would not wait 5 seconds but instead keep retrying until the link disappears, but according to
        // Cypress docs it explicitly will NOT retry a .click() command. See:
        //   https://docs.cypress.io/guides/core-concepts/retry-ability.html#Why-are-some-commands-NOT-retried
        //   https://www.cypress.io/blog/2019/01/22/when-can-the-test-click/
        // The latter suggests to use a 3rd party cypress-pipe plugin and not to use waits. That would be nice, but to
        // use a plugin we then need a custom Docker image which is something I'd rather not build, publish and maintain
        // the moment. TODO: don't publish an image, instead build it on the test runner just before running the tests?
        if ($body.find('#no_resources_click_to_refresh').length > 0) {
          cy.get('#no_resources_click_to_refresh').wait(5000).click().get('body').get('#no_resources_click_to_refresh').should('not.exist')
        }
      })

      // wait for Lagosta to finish fetching the route analysis details
      cy.wait('@analyzeRoutes').its('response.statusCode').should('eq', 200)

      cy.get('div#pane-roas button').contains('Add ROA').click()
      cy.get('div[role="dialog"]')
      cy.contains('Add ROA')
      cy.get('#add_roa_asn').clear().type('AS18')
      cy.get('#add_roa_prefix').clear().type('10.0.0.1/32')
      cy.get('div[role="dialog"] button').contains('Confirm').click()

      if (ts.o) {
        cy.contains('ROA added')
      } else {
        cy.contains('Your user does not have sufficient rights to perform this action. Please contact your administrator.')
      }
    })
  })
})
