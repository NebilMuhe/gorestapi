Feature: login user

    Scenario: validate the input
        Given User is on login page
        When User enters "<Username>" and "<Password>"
        Then The system sholud return an error "<ErrorMessage>"
        Examples:
        | Username   | Password              | ErrorMessage                                        |
        |            | 12QWas@#              | username: username required.                                  |
        | Matheo     |                       | password: password required.                                  |
        | 123455     | 12QWas@#              | username: username must be valid.                             |
        | dave       | 12QWas@#              | username: Username length must be atleast 5 characters.       |
        | david      | 12QWas                | password: Password length must be atleast 8 characters long.  |
        | david      | 12345678              | password: Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.  |
        | david      | 1234ABCD              | password: Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.  |
        | david      | 12ABCDab              | password: Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.  |
        | david1     | 12ABCD%$              | password: Password must contain atleast one uppercase letters,one lowercase letters, digits and special characters.  |
        | abebe1     | 12ABCD%$ab            | not found  |

    Scenario: login request with valid username and password
        Given User is on login page
        When I send "POST" request to url "/api/login" with payload:
        """
        {
            "username": "abebe",
            "password": "12ABCD%$ab"
        }   
        """
        Then the response code should be 200 and issue JWT