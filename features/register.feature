Feature: register user

  Scenario:
    Given User is on registre page
    When User enters "<Username>","<Email>", and "<Password>"
    Then The system sholud return "<ErrorMessage>"
    Examples:
    | Username   | Email                 | Password        | ErrorMessage                               |
    |            | "aslak@gmail.com"     | 12QWas@#        | username required.                         |
    | Matheo     | ""                    | 12QWas@#        | email required.                            |
    | davide     | "david@gmail.com"     |                 | password required.                         |
    | dave       | "dave@gmail.com"      | 12QWas@#        | the length must be between 5 and 20.       |
    | david      | "davegmail.com"       | 12QWas@#        | must be a valid email address.             |
    | david      | "dave@gmail.com"      | 12QWas          | the length must be between 8 and 50.       |
    | david      | "dave@gmail.com"      | 12345678        | must be in a valid format.                 |
    | david      | "dave@gmail.com"      | 1234ABCD        | must be in a valid format.                 |
    | david      | "dave@gmail.com"      | 12ABCDab        | must be in a valid format.                 |
    | david      | "dave@gmail.com"      | 12ABCD%$        | must be in a valid format.                 |