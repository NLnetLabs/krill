describe('Master API token', () => {
  it('Cannot login with empty password', () => {
    cy.visit('/')
    cy.contains('Password')
    cy.get(':password').clear()
    cy.contains('Sign In').click()
    cy.contains('Please enter your password')
  })

  it('Cannot login with incorrect password', () => {
    cy.visit('/')
    cy.contains('Password')
    cy.get(':password').clear().type('abc')
    cy.contains('Sign In').click()
    cy.contains('The credentials you specified are wrong')
  })

  it('Can login with correct password', () => {
    cy.visit('/')
    cy.contains('Password')
    cy.get(':password').type('dummy-test-token')
    cy.contains('Sign In').click()
    cy.contains('Logged in as')
  })
})
