The RustyBGP implementation was designed from scratch to exploit multicore processors for scalability. This documentation describes mainly how threads are used. The key difference from other OSS implementations is parallelizing the routing table processing for scalability for number of routes.

![](https://github.com/osrg/rustybgp/raw/master/.github/assets/thread-design.png)

RustyBGP creates OS threads as roughly many as CPUs, so the overhead of the OS scheduler is kept minimum.

Half of the threads are assigned to peer processing; reading from/sending to a socket, decoding/encoding bgp messages, etc. These threads are called peer thread.
A single peer thread handles multiple peers concurrently with I/O multiplexing system call (e.g., epoll for Linux).

Half of the threads are assigned to routing table processing. The routing table is broken up; sharding routes based on the prefix and the shards are assigned to the threads. These threads are called table thread. Table threads can process routes independently.

In addition to peer and table threads, there is one management thread. The management thread accepts new peer connections, processes gRPC requests/responses, etc. The management thread accesses to the resource that peer and table threads with synchronization primitives (e.g. listing of the routes). When the management thread accepts a new peer socket, it was passed to one of peer threads.

Peer and table threads are connected with asynchronous channels.

Assume that a peer thread receives an update message, including one route. The peer thread decodes the update message and calculates the hash value of the prefix of the route. Then the peer thread sends the route information to an appropriate table thread via channel. The table thread calculates the best path and if necessary, it sends the new best path information to peer threads. Each peer thread encodes update message from the information and sends the message to peers that the peer thread manages.
