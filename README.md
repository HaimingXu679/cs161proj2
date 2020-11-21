# CS 161 Project 2 Design Document
__Haiming Xu (3034177280) and Ru Pei (3034199185)__

### Section 1: System Design

_User Storage_

Users are stored as a struct in the Datastore. This user struct contains the user’s username, password, owned files, files shared with others (more on the file data structures later), and relevant keys (for MAC, RSA decryption, and signing). Note, for the purposes of this design, MAC always refers to HMAC.

When initializing a user, we first create a `masterKey`, which is simply a symmetric encryption key deterministically generated using `Argon2Key` function by passing in the password and salted partially with the username (username + secondary salt). We then populate the struct as follows:
The MAC key is also deterministically generated from the username and password (but is different from the `masterKey` as we use a different secondary salt).
The file data structures are initially empty
Keys for RSA and signing are randomly generated. The public keys are stored in the Keystore (keyed by username + “_rsaek” and username + “_ds”)

We derive the UUID from the first 16 bytes of the hash of `masterKey`. Since hashes are one-way, we don’t have to worry about leaking information. The entire user struct is then marshaled, encrypted with `masterKey`, MACed, and stored in the Datastore.

Getting a user is simple: we can recreate the UUID and check if that user actually exists in the Datastore. The UUID will match iff the username and password match. If it does, we unmarshall, verify the integrity of the struct, and decrypt. There are implementation acrobatics (i.e. padding with PKCS#7) that aren’t too important on the design-level.

_File Storage_

Files are represented as a LinkedList with `MetaData` nodes. Each one of these nodes includes the UUID of itself (for convenience), the next node, the last node if it’s the head, and a `File` struct that contains the actual contents of the file. Note UUIDs are essentially pointers in this context.

For each file, we encrypt and MAC independently (with new encryption and MAC keys) and the same keys are used for all contents that belong to the same file (all `MetaData` and `File` structs, even those that are later appended). Thus, we keep track of a user’s owned files via the `Files` attribute in the user struct. This is a map from filename to a `FileKeys` struct that contains an symmetric encryption key, MAC key, and the UUID of the first `MetaData` node. If this description is somewhat convoluted, refer to figure 1 for a diagram.

1. How is a file stored on the server?

If we’re storing a new file
We randomly generate an encryption and MAC key, and UUIDs for the head `MetaData` node and `File` struct
We initialize a `File` struct and a corresponding `MetaData` node. Marshal, encrypt, MAC, and store on the Datastore
We initialize and add a relevant `FileKeys` struct to a user’s `Files`
If we’re overriding an existing file
We fetch the same info (keys and UUIDs) as the original file (this is important for sharing: we want all shared users to see the changes and be able to decrypt)
We initialize a `File` struct and a corresponding `MetaData` node. Marshal, encrypt, MAC, and store on the Datastore
We clear the head `MetaData`’s Next and End pointer and (if info was appended to the file, it should not exist anymore)

Loading files is as easy as accessing the user’s relevant `FileKeys` struct, fetching the head `MetaData` from the Datastore, and running through the LinkedList while decrypting the information.

4. How does your design support efficient file append?

Our design achieves appending in O(size of appended contents). To append, a user will:
Fetch the end `MetaData` node directly from the head `MetaData` - O(1)
Initialize, marshal, encrypt, MAC, and upload the new `MetaData` and `File` structs to the Datastore - O(size of appended contents) for encryption
Update the end node’s next and the head’s end - O(1)

Since we’re using pointers, this update will also be instantaneously available to all other users this file was shared.


### File Sharing

2. How does a file get shared with another user?

The only two things a user needs to access an existing file: encryption information and the address of the head node. Hence, to share, we can simply send a `magic_string` that’s the marshaled and encrypted version of all that information + a signature. We do exactly with RSA encryption with slight nuance: to better revoke chain sharing, however, we instead append a dummy node to the first `MetaData` node that’s being shared. This node has all the same information but an extraneous `File` UUID (this will be fleshed out when talking about revoking).

On the user end, the user who is sharing the file (owns the file) creates a new entry into their `SharedWithOthers` attribute. This is a map from filename to a map of shared users to the UUID of their head (or dummy) pointer. Ultimately, this keeps track of all files they have permissions to that they’ve shared with others.

Receiving a file is simply decrypting the `magic_string`, verifying the signature, unmarshalling, and adding the file to the recipient’s `Files`.

3. What is the process of revoking a user’s access to a file?

The point (no pun intended) of having a pointer (`FileKeys`) to a pointer (`MetaData`, which is potentially a dummy) to the file contents is to make this process easy. The owner simply has to upload the file to a new UUID and change the revoked user’s head node’s next to garbage. Thus, the revoked user won’t be able to find the new file or any changes that are made.
 
Our design also seamlessly facilitates revoking chain sharing. If user1 shares with user2 who then shares with user3, revoking access to user2 also revokes user3. User2’s dummy pointer will be invalid, and hence, any pointers dependent on it are too.

### Additional Subtleties

We’d like to briefly comment on 2 subtleties.
To support the same user logging in on different instances, we fetch the marshalled user information from the Datastore at the start of every operation, and update it at the end
Filenames are never exposed by files themselves (the file doesn’t even know its own filename). Only the user knows; thus, no information about the names is leaked.

