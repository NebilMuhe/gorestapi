Feature: register user

  Scenario: validate the users input
    Given User is on registre page
    When User enters "<Username>","<Email>", and "<Password>"
    Then The system sholud return "<ErrorMessage>"
    Examples:
    | Username   | Email                 | Password        | ErrorMessage                               |
    |            | "aslak@gmail.com"     | 12QWas@#        | username required.                         |
    | Matheo     | ""                    | 12QWas@#        | email required.                            |
    | davide     | "david@gmail.com"     |                 | password required.                         |
    | 123455     | "david@gmail.com"     | 12QWas@#        | username must be valid.                    |
    | dave       | "dave@gmail.com"      | 12QWas@#        | Username length must be atleast 5 characters.       |
    | david      | "davegmail.com"       | 12QWas@#        | email must be valid.                                |
    | david      | "dave@gmail.com"      | 12QWas          | Password length must be atleast 8 characters long.  |
    | david      | "dave@gmail.com"      | 12345678        | Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.     |
    | david      | "dave@gmail.com"      | 1234ABCD        | Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.     |
    | david      | "dave@gmail.com"      | 12ABCDab        | Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.     |
    | david1     | "dave@gmail.com"      | 12ABCD%$        | Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.     |
  
  Scenario: register user with valid input
    Given User is on registre page
    When I send "POST" request to "/api/register" with payload:
        """
        {
            "username": "abebe",
            "email": "abebe@gmail.com",
            "password": "12ABCD%$ab"
        }   
        """
    Then the response code should be 201
    And the response payload should match json:
        """
          {
            "username": "abebe",
            "email": "abebe@gmail.com"
          }    
        """