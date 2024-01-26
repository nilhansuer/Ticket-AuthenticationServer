# Ticket and Authentication Server Design 
> Secure communication between clients and servers in the network environment.

> Kerberos Protocol Logic is implemented.

### About The Project
- Clients can make authenticated calls to servers in a network environment.
- User authentication mechanisms are used to validate client identities.
- AES decryption and encryption methods in ECB mode are used.

#### Authentication Process

1. The username information that is entered by the user is received by the Authentication Server (AS).
2. To create client’s key, client’s password is used and encrypted.
3. Tgs and server keys are generated randomly.
4. Two messages are created by the AS.
5. First message -> session key encrypted with client’s key.
6. Second message -> a ticket contains username, session key and expiration date encrypted by tgs’s key.
7. In the client side, the client enters the password through the terminal and it is checked whether it matches the decrypted secret key of client.
8. If it matches, the "message containing the session key" is decrypted with the client's secret key and the session key is obtained by the client.
9. A message that contains Ticket and username is encrypted with the session key between client-TGS.
10. A message containing username and timestamp is also encrypted with session key between client-TGS. 
11. And then, client goes to TicketGrantingServer (TGS).
12. Tgs gets the encrypted ticket and timestamp message and decrypts the ticket to obtain session key between client and tgs using tgs’s key.
13. Also, decrypts the message containing username and timestamp with the session key between client-TGS.
14. And compares the username obtained from here with the username obtained in decrypted ticket.
15. If the usernames are matched, TGS creates 2 messages and sends them to the client.
16. One of the messages is session key between Client-Server (encrypt it with session key between client-tgs).
17. The other message is the TOKEN contains session key between Client-server, username and exp_date token and this message is encrypted with server's key.
18. The timestamp obtained from here and exp_date is compared
19. If validation is checked, the client is authenticated.
20. Now, user can update her/his key.
