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
