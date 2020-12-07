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

let admin     = { u: 'admin_nota@krill',     p: 'admin_nota_pass'     };
let readonly  = { u: 'readonly_nota@krill',  p: 'readonly_nota_pass'  };
let readwrite = { u: 'readwrite_nota@krill', p: 'readwrite_nota_pass' };

// For the tests below to work these users must only have access to a single CA,
// otherwise only the first user gets to create a CA, after that Lagosta doesn't
// prompt to create a CA as the user can already see that one exists.
// For the read only user to be able to see the repository and parent management
// UI they must be able to get past the "Welcome to Krill" screen which prompts
// to create a CA, something the read only user cannot do. Therefore the read
// only user should be restricted to seeing the CA created by another user, e.g.
// ca_admin, and should be tested for CA creation failure *before* that CA is
// created.
let init_ca_test_settings = [
  { d: 'readonly',  u: readonly.u,  p: readonly.p,  o: false, ca: 'ca_admin' },
  { d: 'readwrite', u: readwrite.u, p: readwrite.p, o: true,  ca: 'ca_readwrite' },
  { d: 'admin',     u: admin.u,     p: admin.p,     o: true,  ca: 'ca_admin' },
];

describe('Config File Users with TA', () => {
  init_ca_test_settings.forEach(function (ts) {
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

  init_ca_test_settings.forEach(function (ts) {
    it('Register CA ' + ts.ca + ' with repository as ' + ts.d + ' user should ' + (ts.o ? 'succeed' : 'fail'), () => {
      cy.visit('/')
      cy.get('#login_id').type(ts.u)
      cy.get('#login_password').type(ts.p)
      cy.contains('Sign In').click()
      cy.contains(ts.u)
      cy.contains('Sign In').should('not.exist')

      // grab the repository tab publisher request XML from the Krill UI
      cy.get('div#tab-repo').click()
      cy.get('div#pane-repo pre[contenteditable="false"] code').contains('<publisher_request')
      cy.get('div#pane-repo pre[contenteditable="false"] code').invoke('text').then(pub_req_xml => {
        // use the local testbed UI to submit the request to register the publisher
        cy.visit("/index.html#/testbed")

        // enter the request XML into the testbed UI edit field
        cy.get('div#tab-addPublisher').contains('Register Publisher').click()
        cy.get('div#pane-addPublisher pre[contenteditable="true"]').invoke('text', pub_req_xml)
        cy.get('div#pane-addPublisher pre[contenteditable="true"]').type('{end}')
        cy.get('div#pane-addPublisher button').contains('Register publisher').click()
        cy.get('div[role="dialog"] button').contains('OK').click()
        cy.contains('has been added to the testbed')

        // grab the repository response XML from the testbed UI
        cy.get('div#pane-addPublisher pre[contenteditable="false"]').contains('<repository_response')
        cy.get('div#pane-addPublisher pre[contenteditable="false"]').invoke('text').then(repo_resp_xml => {
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
    })
  })

  init_ca_test_settings.forEach(function (ts) {
    it('Register CA ' + ts.ca + ' with parent as ' + ts.d + ' user should ' + (ts.o ? 'succeed' : 'fail'), () => {
      cy.visit('/')
      cy.get('input[placeholder="Your username"]').type(ts.u)
      cy.get(':password').type(ts.p)
      cy.contains('Sign In').click()
      cy.contains(ts.u)
      cy.contains('Sign In').should('not.exist')

      // grab the parents tab child request XML from the Krill UI
      cy.get('div#tab-parents').click()
      cy.get('div#pane-parents pre[contenteditable="false"] code').contains("<child_request")
      cy.get('div#pane-parents pre[contenteditable="false"] code').invoke('text').then(child_req_xml => {
        // use the local testbed UI to submit the request to register the child
        cy.visit("/index.html#/testbed")

        // enter the request XML into the testbed UI edit field
        cy.get('div#tab-addChild').contains('Register CA').click()
        cy.get('div#pane-addChild pre[contenteditable="true"]').invoke('text', child_req_xml)
        cy.get('div#pane-addChild pre[contenteditable="true"]').type('{end}')
        cy.get('div#pane-addChild input[placeholder^="The AS resources"]').type('AS18')
        cy.get('div#pane-addChild input[placeholder^="The IPv4 resources"]').type('10.0.0.0/24')
        cy.get('div#pane-addChild button').contains('Register child CA').click()
        cy.get('div[role="dialog"] button').contains('OK').click()
        cy.contains('has been added to the testbed')

        // grab the parent response XML from the testbed UI
        cy.get('div#pane-addChild pre[contenteditable="false"]').contains("<parent_response")
        cy.get('div#pane-addChild pre[contenteditable="false"]').invoke('text').then(parent_resp_xml => {
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
          } else {
            cy.contains('Success').should('not.exist')
            cy.contains('Error')
          }
        })
      })
    })
  })

  init_ca_test_settings.forEach(function (ts) {
    it('Add ROA for CA ' + ts.ca + ' as ' + ts.d + ' user should ' + (ts.o ? 'succeed' : 'fail'), () => {
      cy.visit('/')
      cy.get('input[placeholder="Your username"]').type(ts.u)
      cy.get(':password').type(ts.p)
      cy.contains('Sign In').click()
      cy.contains(ts.u)
      cy.contains('Sign In').should('not.exist')

      // Add a ROA
      cy.get('div#tab-roas').click()
      cy.get('body').then(($body) => {
        if ($body.find('#no_resources_click_to_refresh').length > 0) {
          cy.get('Click here to refresh').click()
        }
      })
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