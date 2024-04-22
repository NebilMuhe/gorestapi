Feature: register user

  Scenario:
    Given User is on registre page
    When User enters "<Username>","<Email>", and "<Password>"
    Then The system sholud return "<ErrorMessage>"
    Examples:
    | Username   | Email              | Password        | ErrorMessage      |
    |            | aslak@cucumber.io  | 12QWas@#        | username required |
    | Julien     |                    | 12QWas@#        | email required    |
    | Matt       | matt@cucumber.io   |                 | password required |