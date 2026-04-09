describe('UTC timestamp', () => {
  beforeEach(() => {
    cy.visit('/')
  })

  it('displays a correctly-formatted UTC generation date for the first distro', () => {
    cy.get('[data-cy="generated-date"]').first()
      .invoke('text')
      .invoke('trim')
      .should('match', /^Generated \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC$/)
  })
})

describe('Responsive view switching', () => {
  context('Large screen (≥1036px)', () => {
    beforeEach(() => {
      cy.viewport(1280, 900)
      cy.visit('/')
    })

    it('shows the data table and hides the cards view', () => {
      cy.get('[data-cy="data-table"]').first().should('be.visible')
      cy.get('[data-cy="cards-view"]').first().should('not.be.visible')
    })

    it('the data table has at least one row', () => {
      cy.get('[data-cy="data-table"] tbody tr').should('have.length.at.least', 1)
    })
  })

  context('Small screen (<1036px)', () => {
    beforeEach(() => {
      cy.viewport(768, 900)
      cy.visit('/')
    })

    it('shows the cards view and hides the data table', () => {
      cy.get('[data-cy="cards-view"]').first().should('be.visible')
      cy.get('[data-cy="data-table"]').first().should('not.be.visible')
    })

    it('the cards view has at least one card', () => {
      cy.get('[data-cy="cards-view"] .p-card').should('have.length.at.least', 1)
    })
  })
})

describe('Table sorting', () => {
  beforeEach(() => {
    cy.viewport(1280, 900)
    cy.visit('/')
  })

  it('clicking the Severity header sorts ascending and sets aria-sort', () => {
    cy.get('.vuln-sort-btn[data-col="severity"]').first().click()
    cy.get('[data-cy="data-table"] th[aria-sort="ascending"]').should('exist')
    cy.get('[data-cy="data-table"] tbody tr').should('have.length.at.least', 1)
  })

  it('clicking the Severity header twice sorts descending', () => {
    cy.get('.vuln-sort-btn[data-col="severity"]').first().click()
    cy.get('.vuln-sort-btn[data-col="severity"]').first().click()
    cy.get('[data-cy="data-table"] th[aria-sort="descending"]').should('exist')
    cy.get('[data-cy="data-table"] tbody tr').should('have.length.at.least', 1)
  })

  it('clicking the CVE ID header sorts ascending and renders rows', () => {
    cy.get('.vuln-sort-btn[data-col="cve_id"]').first().click()
    cy.get('[data-cy="data-table"] th[aria-sort="ascending"]').should('exist')
    cy.get('[data-cy="data-table"] tbody tr').should('have.length.at.least', 1)
  })
})
