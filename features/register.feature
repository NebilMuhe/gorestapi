Feature: register user

  Scenario: validate the users input
    Given User is on registre page
    When User enters "<Username>","<Email>", and "<Password>"
    Then The system sholud return "<ErrorMessage>"
    Examples:
    | Username   | Email                 | Password        | ErrorMessage                               |
    |            | "aslak@gmail.com"     | 12QWas@#        | username: username required.                         |
    | Matheo     | ""                    | 12QWas@#        | email: email required.                            |
    | davide     | "david@gmail.com"     |                 | password: password required.                         |
    | 123455     | "david@gmail.com"     | 12QWas@#        | username: username must be valid.                    |
    | dave       | "dave@gmail.com"      | 12QWas@#        | username: Username length must be atleast 5 characters.       |
    | david      | "davegmail.com"       | 12QWas@#        | email: email must be valid.                                |
    | david      | "dave@gmail.com"      | 12QWas          | password: Password length must be atleast 8 characters long.  |
    | david      | "dave@gmail.com"      | 12345678        | password: Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.     |
    | david      | "dave@gmail.com"      | 1234ABCD        | password: Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.     |
    | david      | "dave@gmail.com"      | 12ABCDab        | password: Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.     |
    | david1     | "dave@gmail.com"      | 12ABCD%$        | password: Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.     |
    | testuser   | "testuser@gmail.com"  | 12ABcd%$        | user already exists     |
  
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
