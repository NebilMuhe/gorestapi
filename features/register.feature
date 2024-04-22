Feature: register user

  Scenario:
    Given User is on registre page
    When User enters "<Username>","<Email>", and "<Password>"
    Then The system sholud return "<ErrorMessage>"
    Examples:
    | Username   | Email              | Password        | ErrorMessage       |
    |            | "aslak@gmail.com"  | 12QWas@#        | username required. |
    | Matheo     | ""                 | 12QWas@#        | email required.    |
    | davidr     | "david@gmail.com"  |                 | password required. |