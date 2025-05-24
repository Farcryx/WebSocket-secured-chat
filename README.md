# Chat Application Documentation

## Overview
This chat application is designed with a focus on network security. It uses a client-server architecture and implements secure communication protocols, including Diffie-Hellman key exchange and AES encryption.

## Server Functionality
The server is responsible for managing client connections, handling authentication, and facilitating secure communication. It is implemented in `server.py` and uses the following components:

1. **Initialization**:
   - The server reads its IP address and port from `server.json`.
   - It creates a UDP socket and binds it to the specified address and port.

2. **Authentication**:
   - The `AuthenticationManager` class manages unauthenticated and authenticated clients.
   - Clients are authenticated using a combination of Diffie-Hellman key exchange and AES encryption.

3. **Message Handling**:
   - The server listens for incoming messages from clients.
   - It processes different types of messages, such as connection requests, authentication requests, and chat messages.
   - Messages are broadcasted to all authenticated clients except the sender.

## Secure Communication
The application ensures secure communication using the following mechanisms:

1. **Diffie-Hellman Key Exchange**:
   - Used to establish a shared session key between the client and server without transmitting the key directly.

2. **AES Encryption**:
   - Messages are encrypted using AES-GCM to ensure confidentiality and integrity.

3. **Authentication**:
   - Clients must authenticate with the server using a username and password.
   - Passwords are hashed using SHA-256 and stored in `clients.json`.

## Running the Server
   ```bash
   python3 server.py
   ```

## Future Improvements
- [x] Check if the Diffie-Hellman Key Exchange is implemented correctly
- [x] Secured signup and signin requests using AES-GCM
- [ ] Secured broadcast messages
- [ ] Secured direct messages
