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

let publisher_request_test_settings = [
  { desc: 'Compact publisher request XML is accepted',                                            fixture: 'testbed/publisher_request_compact.xml',                                       httpCode: 200 },
  { desc: 'Publisher request with whitespace is accepted',                                        fixture: 'testbed/publisher_request_with_whitespace.xml',                               httpCode: 200 },
  { desc: 'Publisher request with invalid Base64 certificate is rejected by Lagosta',             fixture: 'testbed/publisher_request_invalid_base64.xml',                                httpCode: 'n/a', errMsg: 'Element <publisher_bpki_ta> must contain a correctly Base64 encoded self-signed X.509 BPKI certificate' },
  { desc: 'Publisher request with unicode space char is rejected by Lagosta',                     fixture: 'testbed/publisher_request_with_unicode_space_char.xml',                       httpCode: 'n/a', errMsg: 'Element <publisher_bpki_ta> cannot contain non-ASCII characters' },
  { desc: 'Publisher request with unicode space entity reference is rejected by Lagosta',         fixture: 'testbed/publisher_request_with_unicode_space_entity_reference.xml',           httpCode: 'n/a', errMsg: 'Element <publisher_bpki_ta> cannot contain non-ASCII characters' },
  { desc: 'Publisher request with unicode space entity reference in handle is rejected by Krill', fixture: 'testbed/publisher_request_with_unicode_space_entity_reference_in_handle.xml', httpCode: 400,   errMsg: 'Input contains non-ASCII chars (maybe whitespace?)' },
];

let child_request_test_settings = [
  { desc: 'Compact child request XML is accepted',                                                fixture: 'testbed/child_request_compact.xml',                                           httpCode: 200 },
  { desc: 'Child request with whitespace is accepted',                                            fixture: 'testbed/child_request_with_whitespace.xml',                                   httpCode: 200 },
  { desc: 'Child request with invalid Base64 certificate is rejected by Lagosta',                 fixture: 'testbed/child_request_invalid_base64.xml',                                    httpCode: 'n/a', errMsg: 'Element <child_bpki_ta> must contain a correctly Base64 encoded self-signed X.509 BPKI certificate' },
  { desc: 'Child request with unicode space char is rejected by Lagosta',                         fixture: 'testbed/child_request_with_unicode_space_char.xml',                           httpCode: 'n/a', errMsg: 'Element <child_bpki_ta> cannot contain non-ASCII characters' },
  { desc: 'Child request with unicode space entity reference is rejected by Lagosta',             fixture: 'testbed/child_request_with_unicode_space_entity_reference.xml',               httpCode: 'n/a', errMsg: 'Element <child_bpki_ta> cannot contain non-ASCII characters' },
  { desc: 'Child request with unicode space entity reference in handle is rejected by Krill',     fixture: 'testbed/child_request_with_unicode_space_entity_reference_in_handle.xml',     httpCode: 400,   errMsg: 'Input contains non-ASCII chars (maybe whitespace?)' },
];

describe('Testbed UI test', () => {
  publisher_request_test_settings.forEach(function (ts) {
    it(ts.desc, () => {
      cy.fixture(ts.fixture).then((xml) => {
        // use the local testbed UI to submit the request to register the publisher
        cy.visit("/index.html#/testbed")

        // verify that the register child tab is active by default
        cy.get('#addChild').contains('Child Request XML').should('be.visible')

        // enter the request XML into the testbed UI edit field
        cy.get('div#tab-addPublisher').contains('Register Publisher').click()
        cy.get('#addPublisher pre[contenteditable="true"]').invoke('text', xml)
        cy.get('#addPublisher pre[contenteditable="true"]').type('{end}')

        cy.intercept({ method: 'POST', path: '/testbed/publishers'}).as('addPublisher')
        cy.get('#addPublisher button').contains('Register publisher').click()

        if (ts.httpCode != 'n/a') {
          cy.get('div[role="dialog"] button').contains('OK').click()
          cy.wait('@addPublisher').its('response.statusCode').should('eq', ts.httpCode)
        }

        if (ts.httpCode == 200) {
          cy.contains('has been added to the testbed')
        } else {
          cy.contains(ts.errMsg)
        }
      })
    })
  })

  child_request_test_settings.forEach(function (ts) {
    it(ts.desc, () => {
      cy.fixture(ts.fixture).then((xml) => {
        // use the local testbed UI to submit the request to register the child
        cy.visit("/index.html#/testbed")

        // enter the request XML into the testbed UI edit field
        cy.get('div#tab-addChild').contains('Register CA').click()
        cy.get('#addChild pre[contenteditable="true"]').invoke('text', xml)
        cy.get('#addChild pre[contenteditable="true"]').type('{end}')
        cy.get('#addChild input[placeholder^="The AS resources"]').type('AS18')
        cy.get('#addChild input[placeholder^="The IPv4 resources"]').type('10.0.0.0/24')

        cy.intercept({ method: 'POST', path: '/testbed/children'}).as('addChild')
        cy.get('#addChild button').contains('Register child CA').click()

        if (ts.httpCode != 'n/a') {
          cy.get('div[role="dialog"] button').contains('OK').click()
          cy.wait('@addChild').its('response.statusCode').should('eq', ts.httpCode)
        }
        if (ts.httpCode == 200) {
          cy.contains('has been added to the testbed')
        } else {
          cy.contains(ts.errMsg)
        }
      })
    })
  })
})