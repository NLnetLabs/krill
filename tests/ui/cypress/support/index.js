// This file is loaded by Cypress because cypress.js (in the root of the Krill
// repository) sets "supportFile" to point to this file.
//
// As advised by Cypress *1, prevent Cypress sometimes failing tests due to
// error "ResizeObserver loop limit exceeded" errors.
//
// *1: jennifer@cypress.io aka https://github.com/jennifer-shehane who wrote
//     the following at *2 which was linked from *3:
//
//     const resizeObserverLoopErrRe = /^ResizeObserver loop limit exceeded/
//     
//     Cypress.on('uncaught:exception', (err) => {
//       if (resizeObserverLoopErrRe.test(err.message)) {
//         // returning false here prevents Cypress from
//         // failing the test
//         return false
//       }
//     })
//
// *2: https://github.com/quasarframework/quasar/issues/2233#issuecomment-492975745
// *3: https://github.com/WICG/resize-observer/issues/38#issuecomment-493014026
//
// See also:
//   - https://github.com/cypress-io/cypress-example-recipes/blob/master/examples/fundamentals__errors/cypress/integration/app-error.js
//   - https://docs.cypress.io/api/events/catalog-of-events.html#Uncaught-Exceptions
//   - https://docs.cypress.io/guides/core-concepts/writing-and-organizing-tests.html#Support-file
//   - https://stackoverflow.com/questions/49384120/resizeobserver-loop-limit-exceeded/63519375#63519375
//   - https://github.com/WICG/resize-observer/issues/38

// Define a custom uncaught exception handling policy for Cypress.
// Returning false prevents Cypress from failing the test.
Cypress.on('uncaught:exception', (err, runnable) => {
    console.log("Krill UI Test: Examining uncaught exception..")
    console.log("Krill UI Test: err: ", err)

    if (err.message) {
        if (err.message.includes('ResizeObserver loop limit exceeded')) {
            console.log("Krill UI Test: Ignoring 'ResizeObserver loop limit exceeded' exception")
            return false
        }
        if (err.message.includes('Redirected when going from')) {
            // This happens when going from "/onboarding" to "/interstitial" via a navigation guard and is triggered
            // when logging out of Krill.
            // TODO: Is it safe to ignore this or is this pointing to a real bug in Lagosta?
            console.log("Krill UI Test: Ignoring 'Redirected when going from' exception")
            return false
        }
    }

    // on any other error message the test fails
    console.log("Krill UI Test: Failing the test")
})

